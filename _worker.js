// 代码基本都抄的CM和AK大佬和天书大佬的项目，在此感谢各位大佬的无私奉献。
import {connect} from 'cloudflare:sockets';
const defaultUuid = ''; // 可在环境变量配置，变量名称为UUID，两个地方都不写为不验证uuid
const defaultPassword = ''; // 可在环境变量配置，变量名称为PASSWORD，两个地方都不写为不验证密码
const socks5AndHttpUser = ''; // 可在环境变量配置，变量名称为S5HTTPUSER，两个地方都不写为不验证密码
const socks5AndHttpPass = ''; // 可在环境变量配置，变量名称为S5HTTPPASS，两个地方都不写为不验证密码
const ssAeadPassword = ''; // 可在环境变量配置，变量名称为SSPASS
// ---------------------------------------------------------------------------------
// 理论最低带宽计算公式 (Theoretical Max Bandwidth Calculation):
//    - 速度上限 (Mbps) = (bufferSize (字节) / flushTime (毫秒)) * 0.008
//    - 示例: (512 * 1024 字节 / 10 毫秒) * 0.008 ≈ 419 Mbps
//    - 在此模式下，这两个参数共同构成了一个精确的速度限制器。
// 为有效降低下载大文件可能爆内存的风险，需要自行根据网络单线程速度计算参数。
// ---------------------------------------------------------------------------------
/** 缓冲区最大大小。*/
/**- **警告**: 大小为maxChunkLen的整数倍使用率最高，不然会有空间浪费。*/
const bufferSize = 512 * 1024;         // 512KB
/** 开启限速缓存模式的大包流量阈值。*/
const startThreshold = 50 * 1024 * 1024; //50MB
/** 从TCP读取的数据块最大大小，改小会成倍增加传输相同流量的cpu开销，同时会因为写满而增加数据进入缓冲区限速的概率*/
/**- **警告**: 大小必须为2的幂，设置到大于64KB后只会写满写64KB*/
/**- **警告**: 免费worker设置64KB时传输相同流量cpu开销最低。*/
const maxChunkLen = 64 * 1024;        // 64KB
/** 进入缓冲模式时的缓冲区发送的触发时间。*/
const flushTime = 20;                 // 20ms
// ---------------------------------------------------------------------------------
/** SS AEAD加密时每批并发处理的payload分片数量，length加密开销低，会随payload一起提交。*/
const ssAeadEncryptCount = 4;
// ---------------------------------------------------------------------------------
/**- **警告**: worker最大支持6，超过6没意义*/
let concurrency = 4;//socket获取并发数
// ---------------------------------------------------------------------------------
const urlParamCacheLimit = 20;//URL参数解析结果缓存条数
// ---------------------------------------------------------------------------------
//五者的socket获取顺序，全局模式下为这五个的顺序，非全局为：直连>socks>http>https>turn>nat64>proxyip>finallyProxyHost
const proxyStrategyOrder = ['socks', 'http', 'https', 'turn', 'nat64'];
const sharedEchDns = 'lido.fi+https://223.5.5.5/dns-query'; //ECHDNS配置
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};//分区域proxyip
const finallyProxyHost = 'ProxyIP.CMLiussss.net';//兜底proxyip
// 订阅和面板使用的优选ip地址，可支持ip:port#name格式
const ipListAll = ["172.64.154.125","104.18.39.123","172.64.145.18","104.18.42.218","104.18.33.131","172.64.145.38","172.64.145.202","104.18.42.151"];
const coloRegions = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map();
for (const [region, colos] of Object.entries(coloRegions)) {for (const colo of colos) coloToProxyMap.set(colo, proxyIpAddrs[region])}
const textEncoder = new TextEncoder(), textDecoder = new TextDecoder();
import wasmModule from './protocol.wasm';
const instance = new WebAssembly.Instance(wasmModule);
const {
    memory, getUuidPtr, getResultPtr, getDataPtr, getHttpAuthPtr, getSocks5AuthPtr, setHttpAuthLenWasm, setSocks5AuthLenWasm, parseProtocolWasm, parseUrlWasm,
    initCredentialsWasm, getPanelHtmlPtr, getPanelHtmlLen, getErrorHtmlPtr, getErrorHtmlLen, getCorrectAddrTypeWasm, getTemplateWasm, getSecretStringWasm
} = instance.exports;
const wasmMem = new Uint8Array(memory.buffer);
const wasmRes = new Int32Array(memory.buffer, getResultPtr(), 32);
const dataPtr = getDataPtr();
let isInitialized = false, rawHtml = null, rawErrorHtml = null, config = null, cachedTemplates = null, strList = null, userAgentSuffix = null;
const decompressWasm = async (ptrFn, lenFn) => {
    const ptr = ptrFn(), len = lenFn();
    const compressedData = wasmMem.subarray(ptr, ptr + len);
    const ds = new DecompressionStream("gzip");
    const writer = ds.writable.getWriter();
    writer.write(compressedData);
    writer.close();
    return await new Response(ds.readable).text();
};
const getEnv = (env) => {
    if (config) return config;
    config = {
        uuid: (env.UUID || defaultUuid).trim(),
        password: (env.PASSWORD || defaultPassword).trim(),
        user: (env.S5HTTPUSER || socks5AndHttpUser).trim(),
        pass: (env.S5HTTPPASS || socks5AndHttpPass).trim(), 
        sspass: (env.SSPASS || ssAeadPassword).trim()
    };
    return config;
};
const initializeWasm = (env) => {
    const {uuid, password, user, pass} = getEnv(env);
    const cleanUuid = uuid.replace(/-/g, "");
    if (cleanUuid.length === 32) {
        wasmRes[0] = 1;
        const uuidBytes = new Uint8Array(16);
        for (let i = 0, c; i < 16; i++) {uuidBytes[i] = (((c = cleanUuid.charCodeAt(i * 2)) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = cleanUuid.charCodeAt(i * 2 + 1)) > 64 ? c + 9 : c) & 0xF);}
        wasmMem.set(uuidBytes, getUuidPtr());
    }
    if (password.length > 0) {
        wasmRes[1] = 1;
        const passBytes = textEncoder.encode(password);
        wasmMem.set(passBytes, dataPtr);
        initCredentialsWasm(passBytes.length);
    }
    if (user && pass) {
        const authBytes = textEncoder.encode(btoa(`${user}:${pass}`));
        wasmMem.set(authBytes, getHttpAuthPtr());
        setHttpAuthLenWasm(authBytes.length);
        const userBytes = textEncoder.encode(user);
        const passBytes = textEncoder.encode(pass);
        const socks5Pkg = new Uint8Array(3 + userBytes.length + passBytes.length);
        socks5Pkg[0] = 1, socks5Pkg[1] = userBytes.length, socks5Pkg.set(userBytes, 2), socks5Pkg[2 + userBytes.length] = passBytes.length, socks5Pkg.set(passBytes, 3 + userBytes.length);
        wasmMem.set(socks5Pkg, getSocks5AuthPtr());
        setSocks5AuthLenWasm(socks5Pkg.length);
    }
    cachedTemplates = new Array(12);
    const subUuid = uuid || crypto.randomUUID();
    const subPassword = password || crypto.randomUUID();
    globalThis.subUuid = subUuid;
    const getSecret = (idx) => {
        const len = getSecretStringWasm(idx);
        return textDecoder.decode(wasmMem.subarray(dataPtr, dataPtr + len));
    };
    strList = new Array(20);
    for (let i = 0; i < 20; i++) {strList[i] = getSecret(i)}
    const edge = strList[2];
    userAgentSuffix = edge + strList[3] + edge + strList[4];
    for (let i = 0; i < 12; i++) {
        const len = getTemplateWasm(i);
        const tmpl = textDecoder.decode(wasmMem.subarray(dataPtr, dataPtr + len));
        const baseTmpl = tmpl.replaceAll("{{ECHDNS}}", encodeURIComponent(sharedEchDns));
        cachedTemplates[i] = i < 6 ? baseTmpl.replaceAll("{{UUID}}", subUuid) : baseTmpl.replaceAll("{{PASSWORD}}", subPassword);
    }
    isInitialized = true;
};
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`;
};
const emptyU8 = new Uint8Array(0), ssSubkeyInfo = textEncoder.encode('ss-subkey');
const incNonce = (nonce) => {
    for (let i = 0; i < 12; i++) {
        nonce[i] = (nonce[i] + 1) & 0xff;
        if (nonce[i] !== 0) break;
    }
};
let ssMasterKeyPromise, ssHkdfKeyPromise;
const createSsAeadCtx = async (salt = crypto.getRandomValues(new Uint8Array(16))) => {
    const hkdfKey = await (ssHkdfKeyPromise ||= (async () => {
        const masterKey = await (ssMasterKeyPromise ||= (async () => {
            const pwd = textEncoder.encode(config.sspass);
            const out = new Uint8Array(16);
            let prev = emptyU8, offset = 0;
            while (offset < 16) {
                const input = new Uint8Array(prev.length + pwd.length);
                if (prev.length) input.set(prev, 0);
                input.set(pwd, prev.length);
                prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
                const copyLen = Math.min(prev.length, 16 - offset);
                out.set(prev.subarray(0, copyLen), offset);
                offset += copyLen;
            }
            return out;
        })());
        return crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
    })());
    const subKey = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-1', salt, info: ssSubkeyInfo}, hkdfKey, 128));
    return {
        salt,
        key: await crypto.subtle.importKey('raw', subKey, {name: 'AES-GCM', length: 128}, false, ['encrypt', 'decrypt']),
        nonce: new Uint8Array(12),
        pendingBuf: new Uint8Array(0),
        pendingStart: 0,
        pendingEnd: 0,
        nextPayloadLen: -1,
        nextNeed: 0
    };
};
const ssAeadDecryptFeed = async (ctx, chunk, onPlain) => {
    if (chunk?.length) {
        const chunkLen = chunk.length;
        const pendingLen = ctx.pendingEnd - ctx.pendingStart;
        if (!pendingLen) {
            if (chunkLen > ctx.pendingBuf.length) ctx.pendingBuf = new Uint8Array(chunkLen);
            ctx.pendingBuf.set(chunk, 0);
            ctx.pendingStart = 0;
            ctx.pendingEnd = chunkLen;
        } else {
            if (ctx.pendingBuf.length - ctx.pendingEnd < chunkLen) {
                if (ctx.pendingStart > 0) {
                    ctx.pendingBuf.copyWithin(0, ctx.pendingStart, ctx.pendingEnd);
                    ctx.pendingEnd = pendingLen;
                    ctx.pendingStart = 0;
                }
                if (ctx.pendingBuf.length - ctx.pendingEnd < chunkLen) {
                    const nextCap = pendingLen + chunkLen;
                    const nextBuf = new Uint8Array(nextCap);
                    nextBuf.set(ctx.pendingBuf.subarray(ctx.pendingStart, ctx.pendingEnd), 0);
                    ctx.pendingBuf = nextBuf;
                    ctx.pendingStart = 0;
                    ctx.pendingEnd = pendingLen;
                }
            }
            ctx.pendingBuf.set(chunk, ctx.pendingEnd);
            ctx.pendingEnd += chunkLen;
        }
    }
    const out = onPlain ? null : [];
    let total = 0, pendingStart = ctx.pendingStart, pendingEnd = ctx.pendingEnd;
    const pendingBuf = ctx.pendingBuf;
    while (true) {
        const pendingLen = pendingEnd - pendingStart;
        if (ctx.nextPayloadLen < 0) {
            if (pendingLen < 18) break;
            let lenPlain;
            try {
                lenPlain = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: ctx.nonce, tagLength: 128}, ctx.key, pendingBuf.subarray(pendingStart, pendingStart + 18)));
            } catch {throw new Error('ss length decrypt failed')}
            incNonce(ctx.nonce);
            const payloadLen = (lenPlain[0] << 8) | lenPlain[1];
            if (payloadLen > 16383) throw new Error('ss payload too large');
            ctx.nextPayloadLen = payloadLen;
            ctx.nextNeed = 18 + payloadLen + 16;
        }
        if (pendingLen < ctx.nextNeed) break;
        let payload;
        try {
            payload = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: ctx.nonce, tagLength: 128}, ctx.key, pendingBuf.subarray(pendingStart + 18, pendingStart + ctx.nextNeed)));
        } catch {throw new Error('ss payload decrypt failed')}
        incNonce(ctx.nonce);
        pendingStart += ctx.nextNeed;
        ctx.nextPayloadLen = -1;
        ctx.nextNeed = 0;
        if (onPlain) await onPlain(payload);
        else out.push(payload), total += payload.length;
    }
    if (pendingStart === pendingEnd) {
        ctx.pendingStart = 0;
        ctx.pendingEnd = 0;
    } else {
        ctx.pendingStart = pendingStart;
        ctx.pendingEnd = pendingEnd;
    }
    if (onPlain || out.length === 0) return emptyU8;
    if (out.length === 1) return out[0];
    const merged = new Uint8Array(total);
    for (let i = 0, o = 0; i < out.length; i++) {
        merged.set(out[i], o);
        o += out[i].length;
    }
    return merged;
};
const ssAeadEncryptChunks = async (ctx, data) => {
    if (!data?.length) return emptyU8;
    const dataLen = data.length;
    const out = new Uint8Array(dataLen + Math.ceil(dataLen / 16383) * 34);
    const {key, nonce} = ctx;
    const subtle = crypto.subtle;
    let outOffset = 0;
    for (let base = 0; base < dataLen; base += 16383 * ssAeadEncryptCount) {
        const batchEnd = Math.min(base + 16383 * ssAeadEncryptCount, dataLen);
        const tasks = [];
        for (let offset = base; offset < batchEnd; offset += 16383) {
            const end = offset + 16383 < dataLen ? offset + 16383 : dataLen;
            const p = offset === 0 && end === dataLen ? data : data.subarray(offset, end), l = end - offset;
            const lenBuf = new Uint8Array([l >> 8, l & 0xff]);
            const lenIv = nonce.slice();
            incNonce(nonce);
            const dataIv = nonce.slice();
            incNonce(nonce);
            tasks.push((async () => {
                const lenCipher = await subtle.encrypt({name: 'AES-GCM', iv: lenIv, tagLength: 128}, key, lenBuf);
                const dataCipher = await subtle.encrypt({name: 'AES-GCM', iv: dataIv, tagLength: 128}, key, p);
                return {l, lenCipher, dataCipher};
            })());
        }
        const results = await Promise.all(tasks);
        for (let i = 0; i < results.length; i++) {
            const {l, lenCipher, dataCipher} = results[i];
            out.set(new Uint8Array(lenCipher), outOffset);
            outOffset += 18;
            out.set(new Uint8Array(dataCipher), outOffset);
            outOffset += l + 16;
        }
    }
    return out;
};
const parseHostPort = (addr, defaultPort) => {
    let host = addr, port = defaultPort, idx;
    if (addr.charCodeAt(0) === 91) {
        if ((idx = addr.indexOf(']:')) !== -1) {
            host = addr.substring(0, idx + 1);
            port = addr.substring(idx + 2);
        }
    } else if ((idx = addr.indexOf('.tp')) !== -1 && addr.lastIndexOf(':') === -1) {
        port = addr.substring(idx + 3, addr.indexOf('.', idx + 3));
    } else if ((idx = addr.lastIndexOf(':')) !== -1) {
        host = addr.substring(0, idx);
        port = addr.substring(idx + 1);
    }
    return [host, (port = parseInt(port), isNaN(port) ? defaultPort : port)];
};
const parseSubNode = (entry) => {
    const raw = (entry || '').trim();
    if (!raw) return null;
    const hashIndex = raw.indexOf('#');
    const endpoint = hashIndex === -1 ? raw : raw.slice(0, hashIndex).trim();
    const customName = hashIndex === -1 ? '' : raw.slice(hashIndex + 1).trim();
    const [ip, portNum] = parseHostPort(endpoint || raw, 443);
    return {ip, port: String(portNum), name: customName || ip};
};
const parseAuthString = (authParam) => {
    let username, password, hostStr;
    const atIndex = authParam.lastIndexOf('@');
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(':');
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1);
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username, password, hostname, port};
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname, port}, socketOptions)) => socket.opened.then(() => socket);
const concurrentConnect = (hostname, port, limit = concurrency, socketOptions) => {
    if (limit === 1) return createConnect(hostname, port, socketOptions);
    return Promise.any(Array(limit).fill(null).map(() => createConnect(hostname, port, socketOptions)));
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes, limit) => {
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, limit);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    const {value: authResponse} = await reader.read();
    if (!authResponse || authResponse[0] !== 5 || authResponse[1] === 0xFF) return null;
    if (authResponse[1] === 2) {
        if (!socksAuth.username) return null;
        const userBytes = textEncoder.encode(socksAuth.username);
        const passBytes = textEncoder.encode(socksAuth.password || '');
        const uLen = userBytes.length, pLen = passBytes.length, authReq = new Uint8Array(3 + uLen + pLen)
        authReq[0] = 1, authReq[1] = uLen, authReq.set(userBytes, 2), authReq[2 + uLen] = pLen, authReq.set(passBytes, 3 + uLen);
        await writer.write(authReq);
        const {value: authResult} = await reader.read();
        if (!authResult || authResult[0] !== 1 || authResult[1] !== 0) return null;
    } else if (authResponse[1] !== 0) {return null}
    const isDomain = targetAddrType === 3, socksReq = new Uint8Array(6 + addrBytes.length + (isDomain ? 1 : 0));
    socksReq[0] = 5, socksReq[1] = 1, socksReq[2] = 0, socksReq[3] = targetAddrType;
    isDomain ? (socksReq[4] = addrBytes.length, socksReq.set(addrBytes, 5)) : socksReq.set(addrBytes, 4);
    socksReq[socksReq.length - 2] = targetPortNum >> 8, socksReq[socksReq.length - 1] = targetPortNum & 0xff;
    await writer.write(socksReq);
    const {value: finalResponse} = await reader.read();
    if (!finalResponse || finalResponse[1] !== 0) return null;
    writer.releaseLock(), reader.releaseLock();
    return socksSocket;
};
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, limit, useTls = false) => {
    const {username, password, hostname, port} = httpAuth;
    const connectOptions = useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined;
    const proxySocket = await concurrentConnect(hostname, port, limit, connectOptions);
    const writer = proxySocket.writable.getWriter();
    const httpHost = binaryAddrToString(targetAddrType, addrBytes);
    let dynamicHeaders = `CONNECT ${httpHost}:${targetPortNum} HTTP/1.1\r\nHost: ${httpHost}:${targetPortNum}\r\n`;
    if (username) dynamicHeaders += `Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}\r\n`;
    const fullHeaders = new Uint8Array(dynamicHeaders.length * 3 + encodedStaticHeaders.length);
    const {written} = textEncoder.encodeInto(dynamicHeaders, fullHeaders);
    fullHeaders.set(encodedStaticHeaders, written);
    await writer.write(fullHeaders.subarray(0, written + encodedStaticHeaders.length));
    writer.releaseLock();
    const reader = proxySocket.readable.getReader();
    const buffer = new Uint8Array(512);
    let bytesRead = 0, statusChecked = false;
    while (bytesRead < buffer.length) {
        const {value, done} = await reader.read();
        if (done || bytesRead + value.length > buffer.length) return null;
        const prevBytesRead = bytesRead;
        buffer.set(value, bytesRead);
        bytesRead += value.length;
        if (!statusChecked && bytesRead >= 12) {
            if (buffer[9] !== 50) return null;
            statusChecked = true;
        }
        let i = Math.max(15, prevBytesRead - 3);
        while ((i = buffer.indexOf(13, i)) !== -1 && i <= bytesRead - 4) {
            if (buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) {
                reader.releaseLock();
                return proxySocket;
            }
            i++;
        }
    }
    return null;
};
const magic = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const cat = (...a) => {
    let len = 0, i = 0, o = 0;
    for (; i < a.length; i++) len += a[i].length;
    const r = new Uint8Array(len);
    for (i = 0; i < a.length; i++) {
        r.set(a[i], o);
        o += a[i].length;
    }
    return r;
};
const stunAttr = (t, v) => {
    const l = v.length, b = new Uint8Array(4 + l + (4 - l % 4) % 4);
    b[0] = t >> 8, b[1] = t & 0xff, b[2] = l >> 8, b[3] = l & 0xff, b.set(v, 4);
    return b;
};
const stunMsg = (t, tid, a) => {
    const bd = cat(...a), l = bd.length, h = new Uint8Array(20 + l);
    h[0] = t >> 8, h[1] = t & 0xff, h[2] = l >> 8, h[3] = l & 0xff, h.set(magic, 4), h.set(tid, 8), h.set(bd, 20);
    return h;
};
const xorPeer = (ip, port) => {
    const b = new Uint8Array(8);
    b[1] = 1;
    const xp = port ^ 0x2112;
    b[2] = xp >> 8, b[3] = xp & 0xff;
    let p = 0, num = 0;
    for (let i = 0; i < ip.length; i++) {
        const c = ip.charCodeAt(i);
        if (c === 46) {
            b[4 + p] = num ^ magic[p++];
            num = 0;
        } else {num = num * 10 + (c - 48)}
    }
    b[4 + p] = num ^ magic[p];
    return b;
};
const parseStun = d => {
    if (d.length < 20 || magic.some((v, i) => d[4 + i] !== v)) return null;
    const ml = (d[2] << 8) | d[3], attrs = {};
    for (let o = 20; o + 4 <= 20 + ml;) {
        const t = (d[o] << 8) | d[o + 1], l = (d[o + 2] << 8) | d[o + 3];
        if (o + 4 + l > d.length) break;
        attrs[t] = d.subarray(o + 4, o + 4 + l);
        o += 4 + l + (4 - l % 4) % 4;
    }
    return {type: (d[0] << 8) | d[1], attrs};
};
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const addIntegrity = async (m, cryptoKey) => {
    const l = m.length, c = new Uint8Array(l + 24);
    c.set(m);
    const nl = (m[2] << 8 | m[3]) + 24;
    c[2] = nl >> 8, c[3] = nl & 0xff;
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, c.subarray(0, l)));
    c[l] = 0x00, c[l + 1] = 0x08, c[l + 2] = 0x00, c[l + 3] = 0x14, c.set(sig, l + 4);
    return c;
};
const readStun = async (rd, buf) => {
    let chunks = buf && buf.length ? [buf] : [];
    let total = buf ? buf.length : 0;
    const pull = async () => {
        const {done, value} = await rd.read();
        if (done) throw 0;
        chunks.push(value);
        total += value.length;
    };
    const getB = () => {
        if (chunks.length === 1) return chunks[0];
        const b = new Uint8Array(total);
        let o = 0;
        for (let i = 0; i < chunks.length; i++) {
            b.set(chunks[i], o);
            o += chunks[i].length;
        }
        chunks = [b];
        return b;
    };
    try {
        while (total < 20) await pull();
        let b = getB();
        if (b[4] !== 0x21 || b[5] !== 0x12 || b[6] !== 0xA4 || b[7] !== 0x42) return null;
        const n = 20 + ((b[2] << 8) | b[3]);
        if (n > 8192) return null;
        while (total < n) await pull();
        b = getB();
        return [parseStun(b.subarray(0, n)), total > n ? b.subarray(n) : null];
    } catch {return null}
};
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(s)));
const connectViaTurnProxy = async ({hostname, port, username, password}, targetIp, targetPort) => {
    let ctrl = null, data = null, dataPromise = null;
    const close = () => [ctrl, data].forEach(s => {try {s?.close()} catch {}});
    try {
        ctrl = await createConnect(hostname, port);
        const cw = ctrl.writable.getWriter(), cr = ctrl.readable.getReader();
        const tidBuf = new Uint8Array(12), tid = () => crypto.getRandomValues(tidBuf), tp = new Uint8Array([6, 0, 0, 0]);
        await cw.write(stunMsg(0x003, tid(), [stunAttr(0x019, tp)]));
        let [r, ex] = await readStun(cr);
        if (!r) throw 0;
        let cryptoKey = null, aa = [];
        const sign = m => cryptoKey ? addIntegrity(m, cryptoKey) : m;
        const peer = stunAttr(0x012, xorPeer(targetIp, targetPort));
        if (r.type === 0x113 && username && parseErr(r.attrs[0x009]) === 401) {
            const realm = textDecoder.decode(r.attrs[0x014] ?? []), nonce = r.attrs[0x015] ?? [];
            const keyBytes = await md5(`${username}:${realm}:${password}`);
            cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
            aa = [stunAttr(0x006, textEncoder.encode(username)), stunAttr(0x014, textEncoder.encode(realm)), stunAttr(0x015, nonce)];
            const [am, pm, cm] = await Promise.all([
                sign(stunMsg(0x003, tid(), [stunAttr(0x019, tp), ...aa])),
                sign(stunMsg(0x008, tid(), [peer, ...aa])),
                sign(stunMsg(0x00A, tid(), [peer, ...aa]))
            ]);
            await cw.write(cat(am, pm, cm));
            dataPromise = createConnect(hostname, port);
            [r, ex] = await readStun(cr, ex);
            if (r?.type !== 0x103) throw 0;
        } else if (r.type === 0x103) {
            const [pm, cm] = await Promise.all([
                sign(stunMsg(0x008, tid(), [peer, ...aa])),
                sign(stunMsg(0x00A, tid(), [peer, ...aa]))
            ]);
            await cw.write(cat(pm, cm));
            dataPromise = createConnect(hostname, port);
        } else {throw 0}
        [r, ex] = await readStun(cr, ex);
        if (r?.type !== 0x108) throw 0;
        [r] = await readStun(cr, ex);
        if (r?.type !== 0x10A || !r.attrs[0x02A]) throw 0;
        data = await dataPromise;
        const dw = data.writable.getWriter(), dr = data.readable.getReader();
        await dw.write(await sign(stunMsg(0x00B, tid(), [stunAttr(0x02A, r.attrs[0x02A]), ...aa])));
        let extra;
        [r, extra] = await readStun(dr);
        if (r?.type !== 0x10B) throw 0;
        cr.releaseLock(), cw.releaseLock(), dw.releaseLock(), dr.releaseLock();
        return {readable: data.readable, writable: data.writable, close, extra};
    } catch {
        close();
        return null;
    }
};
const ipv4ToNat64Ipv6 = (ipv4Address, nat64Prefixes) => {
    const parts = ipv4Address.split('.');
    let hexStr = "";
    for (let i = 0; i < 4; i++) {
        let h = (parts[i] | 0).toString(16);
        hexStr += (h.length === 1 ? "0" + h : h);
        if (i === 1) hexStr += ":";
    }
    return `[${nat64Prefixes}${hexStr}]`;
};
const dohJsonOptions = {headers: {'Accept': 'application/dns-json'}}, dohHeaders = {'content-type': 'application/dns-message'};
const concurrentDnsResolve = async (hostname, recordType) => {
    const dnsResult = await Promise.any(dohNatEndpoints.map(endpoint =>
        fetch(`${endpoint}?name=${hostname}&type=${recordType}`, dohJsonOptions).then(response => {
            if (!response.ok) throw new Error();
            return response.json();
        })
    ));
    const answer = dnsResult.Answer || dnsResult.answer;
    if (!answer || answer.length === 0) return null;
    return answer;
};
const dohDnsHandler = async (payload) => {
    if (payload.byteLength < 2) return null;
    const dnsQueryData = payload.subarray(2);
    const resp = await Promise.any(dohEndpoints.map(endpoint =>
        fetch(endpoint, {method: 'POST', headers: dohHeaders, body: dnsQueryData}).then(response => {
            if (!response.ok) throw new Error();
            return response;
        })
    ));
    const dnsQueryResult = await resp.arrayBuffer();
    const udpSize = dnsQueryResult.byteLength;
    const packet = new Uint8Array(2 + udpSize);
    packet[0] = (udpSize >> 8) & 0xff, packet[1] = udpSize & 0xff;
    packet.set(new Uint8Array(dnsQueryResult), 2);
    return packet;
};
const connectNat64 = async (addrType, port, nat64Auth, addrBytes, proxyAll, limit, isHttp) => {
    const nat64Prefixes = nat64Auth.charCodeAt(0) === 91 ? nat64Auth.slice(1, -1) : nat64Auth;
    if (!proxyAll) return concurrentConnect(`[${nat64Prefixes}6815:3598]`, port, limit);
    const hostname = binaryAddrToString(addrType, addrBytes);
    if (isHttp) {
        wasmMem.set(addrBytes, dataPtr);
        addrType = getCorrectAddrTypeWasm(addrBytes.length);
    }
    if (addrType === 3) {
        const answer = await concurrentDnsResolve(hostname, 'A');
        const aRecord = answer?.find(record => record.type === 1);
        return aRecord ? concurrentConnect(ipv4ToNat64Ipv6(aRecord.data, nat64Prefixes), port, limit) : null;
    }
    if (addrType === 1) return concurrentConnect(ipv4ToNat64Ipv6(hostname, nat64Prefixes), port, limit);
    return concurrentConnect(hostname, port, limit);
};
const williamResult = async (william) => {
    const answer = await concurrentDnsResolve(william, 'TXT');
    if (!answer) return null;
    let txtData, i = 0, len = answer.length;
    for (; i < len; i++) if (answer[i].type === 16) {
        txtData = answer[i].data;
        break;
    }
    if (!txtData) return null;
    if (txtData.charCodeAt(0) === 34 && txtData.charCodeAt(txtData.length - 1) === 34) txtData = txtData.slice(1, -1);
    const raw = txtData.split(/,|\\010|\n/), prefixes = [];
    for (i = 0, len = raw.length; i < len; i++) {
        const s = raw[i].trim();
        if (s) prefixes.push(s);
    }
    return prefixes.length ? prefixes : null;
};
const proxyIpRegex = /william|fxpip/;
const connectProxyIp = async (param, limit) => {
    if (proxyIpRegex.test(param)) {
        let resolvedIps = await williamResult(param);
        if (!resolvedIps || resolvedIps.length === 0) return null;
        if (resolvedIps.length > limit) {
            for (let i = resolvedIps.length - 1; i > 0; i--) {
                const j = (Math.random() * (i + 1)) | 0;
                [resolvedIps[i], resolvedIps[j]] = [resolvedIps[j], resolvedIps[i]];
            }
            resolvedIps = resolvedIps.slice(0, limit);
        }
        const connectionPromises = resolvedIps.map(ip => {
            const [host, port] = parseHostPort(ip, 443);
            return createConnect(host, port);
        });
        return await Promise.any(connectionPromises);
    }
    const [host, port] = parseHostPort(param, 443);
    return concurrentConnect(host, port, limit);
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        return concurrentConnect(hostname, port);
    }],
    [1, async ({addrType, port, addrBytes}, param, limit) => {
        return connectViaSocksProxy(addrType, port, param, addrBytes, limit);
    }],
    [2, async ({addrType, port, addrBytes}, param, limit) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes, limit);
    }],
    [6, async ({addrType, port, addrBytes}, param, limit) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes, limit, true);
    }],
    [3, async (_parsedRequest, param, limit) => {
        return connectProxyIp(param, limit);
    }],
    [4, async ({addrType, port, addrBytes, isHttp}, param, limit) => {
        const {nat64Auth, proxyAll} = param;
        return connectNat64(addrType, port, nat64Auth, addrBytes, proxyAll, limit, isHttp);
    }],
    // @ts-ignore
    [5, async ({addrType, port, addrBytes, isHttp}, param) => {
        let targetIp = binaryAddrToString(addrType, addrBytes);
        if (isHttp) {
            wasmMem.set(addrBytes, dataPtr);
            addrType = getCorrectAddrTypeWasm(addrBytes.length);
        }
        if (addrType === 3) {
            const answer = await concurrentDnsResolve(targetIp, 'A');
            const aRecord = answer?.find(record => record.type === 1);
            if (!aRecord) return null;
            targetIp = aRecord.data;
        } else if (addrType === 4) {return null}
        return connectViaTurnProxy(param, targetIp, port);
    }]
]);
const getUrlParam = (offset, len) => {
    if (len <= 0) return null;
    return textDecoder.decode(wasmMem.subarray(dataPtr + offset, dataPtr + offset + len));
};
const urlListCacheDict = Object.create(null), urlListCacheKeys = new Array(urlParamCacheLimit);
let urlListCacheIndex = 0;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), l = clean.length, list = [];
    if (l > 3 && clean.charCodeAt(l - 4) === 47 && clean.charCodeAt(l - 3) === 84 && clean.charCodeAt(l - 2) === 117 && clean.charCodeAt(l - 1) === 110) {
        clean = clean.slice(0, l - 4);
    } else {
        const c = clean.charCodeAt(l - 1);
        if (c === 47 || c === 61) clean = clean.slice(0, l - 1);
    }
    const cachedList = urlListCacheDict[clean];
    if (cachedList !== undefined) {
        list = cachedList;
    } else {
        if (clean.length < 6 || clean.length > 1024) {
            list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
        } else {
            const urlBytes = textEncoder.encode(clean);
            wasmMem.set(urlBytes, dataPtr);
            parseUrlWasm(urlBytes.length);
            const r = wasmRes;
            const s5Val = getUrlParam(r[15], r[16]), httpVal = getUrlParam(r[17], r[18]), nat64Val = getUrlParam(r[19], r[20]), turnVal = getUrlParam(r[24], r[25]), ipVal = getUrlParam(r[21], r[22]), httpsVal = getUrlParam(r[26], r[27]);
            const proxyAll = r[23] === 1;
            !proxyAll && list.push({type: 0});
            const add = (v, t) => {
                if (!v) return;
                const parts = decodeURIComponent(v).split(',').filter(Boolean);
                if (parts.length) {
                    const parsedParams = parts.map(part => {
                        if (t === 4) return {nat64Auth: part, proxyAll};
                        if (t === 1 || t === 2 || t === 5 || t === 6) return parseAuthString(part);
                        return part;
                    });
                    list.push({type: t, param: parsedParams, concurrent: true});
                }
            };
            for (const k of proxyStrategyOrder) k === 'socks' ? add(s5Val, 1) : k === 'http' ? add(httpVal, 2) : k === 'https' ? add(httpsVal, 6) : k === 'turn' ? add(turnVal, 5) : add(nat64Val, 4);
            if (proxyAll) {
                !list.length && list.push({type: 0});
            } else {
                add(ipVal, 3);
                list.push({type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
            }
        }
        const oldKey = urlListCacheKeys[urlListCacheIndex];
        if (oldKey !== undefined) delete urlListCacheDict[oldKey];
        urlListCacheKeys[urlListCacheIndex] = clean;
        urlListCacheDict[clean] = list;
        urlListCacheIndex = (urlListCacheIndex + 1) % urlParamCacheLimit;
    }
    for (let i = 0; i < list.length; i++) {
        try {
            const exec = strategyExecutorMap.get(list[i].type);
            const sub = (list[i].concurrent && Array.isArray(list[i].param)) ? Math.max(1, Math.floor(concurrency / list[i].param.length)) : undefined;
            const socket = await (list[i].concurrent && Array.isArray(list[i].param) ? Promise.any(list[i].param.map(ip => exec(parsedRequest, ip, sub))) : exec(parsedRequest, list[i].param));
            if (socket) return socket;
        } catch {}
    }
    return null;
};
const chunkIdxLookup = new Uint8Array(60);
for (let i = 0; i < 60; i++) {
    let len = i << 9;
    if (len < 1536) chunkIdxLookup[i] = 0;
    else if (len < 2048) chunkIdxLookup[i] = 1;
    else if (len < 2560) chunkIdxLookup[i] = 2;
    else if (len < 3072) chunkIdxLookup[i] = 3;
    else if (len < 3584) chunkIdxLookup[i] = 4;
    else if (len < 4096) chunkIdxLookup[i] = 5;
    else if (len < 5120) chunkIdxLookup[i] = 6;
    else if (len < 6144) chunkIdxLookup[i] = 7;
    else if (len < 7168) chunkIdxLookup[i] = 8;
    else if (len < 8192) chunkIdxLookup[i] = 9;
    else if (len < 12288) chunkIdxLookup[i] = 10;
    else if (len < 20480) chunkIdxLookup[i] = 11;
    else chunkIdxLookup[i] = 12;
}
const lowerBounds = new Uint16Array([1024, 1536, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 12288, 20480, 28672]);
const smartPipeCore = async (readable, onFlush) => {
    const safeBufferSize = bufferSize - maxChunkLen;
    let buffer = new Uint8Array(bufferSize), chunkBuf = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, time = 2, timerId = null, resume = null;
    let globalCount = new Float64Array(14), globalBytes = new Float64Array(14);
    let statCount = 0, totalCount = 0, totalGlobalBytes = 0;
    const flushBuffer = () => {
        offset > 0 && (onFlush(buffer.slice(0, offset)), offset = 0);
        timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const {done, value} = await reader.read(new Uint8Array(chunkBuf));
            if (done) break;
            chunkBuf = value.buffer;
            const chunkLen = value.byteLength;
            if (!chunkLen) continue;
            const idx = chunkLen >= 30720 ? 13 : chunkIdxLookup[chunkLen >> 9];
            globalCount[idx]++, globalBytes[idx] += chunkLen;
            statCount++, totalCount++, totalGlobalBytes += chunkLen;
            if (statCount > 1000000) {
                statCount = 0, totalCount *= 0.5, totalGlobalBytes *= 0.5;
                for (let i = 0; i < 14; i++) globalCount[i] *= 0.5, globalBytes[i] *= 0.5;
            }
            let maxScore = -1, maxIdx = 0;
            const cFactor = 0.8 / totalCount, bFactor = 0.2 / totalGlobalBytes;
            for (let i = 0; i < 14; i++) {
                const score = globalCount[i] * cFactor + globalBytes[i] * bFactor;
                score > maxScore && (maxScore = score, maxIdx = i);
            }
            chunkLen < lowerBounds[maxIdx] && (totalBytes = 0, time = 2);
            buffer.set(value, offset), offset += chunkLen, totalBytes += chunkLen;
            totalBytes > startThreshold && (time = flushTime);
            timerId ||= setTimeout(flushBuffer, time);
            offset > safeBufferSize && (time === flushTime ? await new Promise(r => resume = r) : flushBuffer());
        }
    } finally {flushBuffer(), reader.releaseLock()}
};
const handleSession = async (chunk, state, request, writable, close) => {
    const allowNeedMore = state.allowNeedMore === true;
    if (allowNeedMore) state.needMore = false;
    let parsedRequest, payload, isSs = false;
    const ssEnabled = !state.disableSsAead && !!config?.sspass && !state.tcpWriter && state.socks5State === 0;
    const parseLen = Math.min(chunk.length, 1024);
    wasmMem.set(chunk.subarray(0, parseLen), dataPtr);
    const success = parseProtocolWasm(parseLen, state.socks5State);
    const r = wasmRes;
    const hLen = r[12];
    if (hLen > 0) writable.send(wasmMem.slice(dataPtr, dataPtr + hLen));
    if (!success) {
        if (r[4] > 0) return state.socks5State = r[4];
        if (allowNeedMore && r[14] === 1) return state.needMore = true;
        if (ssEnabled && chunk.length >= 34) {
            try {
                const decryptCtx = await createSsAeadCtx(chunk.subarray(0, 16));
                const plain = await ssAeadDecryptFeed(decryptCtx, chunk.subarray(16));
                const plainLen = plain.length;
                if (plainLen > 0) {
                    const addrType = plain[0];
                    const addrLen = addrType === 3 ? (plainLen > 1 ? plain[1] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
                    if (addrLen !== null && addrLen > 0) {
                        const addrOffset = addrType === 3 ? 2 : 1;
                        const dataOffset = addrOffset + addrLen + 2;
                        if (plainLen >= dataOffset) {
                            const portOffset = dataOffset - 2;
                            const port = (plain[portOffset] << 8) | plain[portOffset + 1];
                            parsedRequest = {addrType, addrBytes: plain.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
                            const encryptCtx = await createSsAeadCtx();
                            isSs = true;
                            payload = plain.subarray(dataOffset);
                            state.ssInbound = decryptCtx;
                            state.ssOutbound = encryptCtx;
                            state.ssResponseSalt = encryptCtx.salt;
                        }
                    }
                }
            } catch {}
        }
        if (!isSs) return close();
    } else {
        state.socks5State = 0;
        parsedRequest = {addrType: r[5], port: r[6], dataOffset: r[7], isDns: r[8] === 1, addrBytes: chunk.subarray(r[9], r[9] + r[10]), isHttp: r[11] === 3};
        payload = chunk.subarray(parsedRequest.dataOffset);
    }
    if (parsedRequest.isDns) {
        const dnsPack = await dohDnsHandler(payload);
        if (dnsPack?.byteLength) {
            if (isSs || state.ssOutbound) {
                if (state.ssResponseSalt) {
                    writable.send(state.ssResponseSalt);
                    state.ssResponseSalt = null;
                }
                const encryptedDns = await ssAeadEncryptChunks(state.ssOutbound, dnsPack);
                if (encryptedDns.byteLength) writable.send(encryptedDns);
            } else {
                writable.send(dnsPack);
            }
        }
        return close();
    } else {
        state.tcpSocket = await establishTcpConnection(parsedRequest, request);
        if (!state.tcpSocket) return close();
        const tcpWriter = state.tcpSocket.writable.getWriter();
        if (payload.byteLength) await tcpWriter.write(payload);
        if (isSs || state.ssOutbound) {
            state.tcpWriter = async (c) => {
                await ssAeadDecryptFeed(state.ssInbound, c instanceof Uint8Array ? c : new Uint8Array(c), async plain => {
                    if (plain.byteLength) await tcpWriter.write(plain);
                });
            };
            state.ssResponseSalt?.length && writable.send(state.ssResponseSalt);
            state.ssResponseSalt = null;
            (async () => {
                let flushPromise = Promise.resolve();
                state.tcpSocket.extra?.length && (flushPromise = flushPromise.then(async () => {
                    const encryptedExtra = await ssAeadEncryptChunks(state.ssOutbound, state.tcpSocket.extra);
                    encryptedExtra.byteLength && writable.send(encryptedExtra);
                }));
                try {
                    await smartPipeCore(state.tcpSocket.readable, raw => {
                        flushPromise = flushPromise.then(async () => {
                            const encrypted = await ssAeadEncryptChunks(state.ssOutbound, raw);
                            encrypted.byteLength && writable.send(encrypted);
                        });
                    });
                } finally {await flushPromise}
            })().finally(() => close());
        } else {
            state.tcpWriter = (c) => tcpWriter.write(c);
            if (state.tcpSocket.extra?.length) writable.send(state.tcpSocket.extra);
            smartPipeCore(state.tcpSocket.readable, raw => writable.send(raw)).finally(() => close());
        }
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const earlyData = protocolHeader ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, ssInbound: null, ssOutbound: null, ssResponseSalt: null};
    const close = () => {state.tcpSocket?.close(), !earlyData && webSocket.close()};
    let processingChain = Promise.resolve();
    const process = async (chunk) => {
        if (state.tcpWriter) return state.tcpWriter(chunk);
        await handleSession(earlyData ? chunk : new Uint8Array(chunk), state, request, webSocket, close);
    };
    if (earlyData) processingChain = processingChain.then(() => process(earlyData).catch(close));
    webSocket.addEventListener("message", event => {processingChain = processingChain.then(() => process(event.data).catch(close))});
};
const grpcHeaders = {'Content-Type': 'application/grpc', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const xhttpHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const handleGrpcPost = async (request, reader, buffer, used) => {
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, ssInbound: null, ssOutbound: null, ssResponseSalt: null};
    return new Response(new ReadableStream({
        start(controller) {
            const writable = {
                send: (chunk) => {
                    const len = chunk.byteLength;
                    let varintLen = 1;
                    for (let v = len >>> 7; v; v >>>= 7) varintLen++;
                    const totalPayloadLen = 1 + varintLen + len;
                    const grpcFrame = new Uint8Array(5 + totalPayloadLen);
                    grpcFrame[0] = 0;
                    grpcFrame[1] = totalPayloadLen >>> 24;
                    grpcFrame[2] = totalPayloadLen >>> 16;
                    grpcFrame[3] = totalPayloadLen >>> 8;
                    grpcFrame[4] = totalPayloadLen;
                    grpcFrame[5] = 0x0A;
                    let p = 6, v = len;
                    while (v > 127) {
                        grpcFrame[p++] = (v & 0x7F) | 0x80;
                        v >>>= 7;
                    }
                    grpcFrame[p++] = v;
                    grpcFrame.set(chunk, p);
                    controller.enqueue(grpcFrame);
                }
            };
            const close = () => {reader.releaseLock(), state.tcpSocket?.close(), controller.close()};
            (async () => {
                let grpcBuffer = new ArrayBuffer(73728), offset = 0;
                if (used) new Uint8Array(grpcBuffer, 0, used).set(buffer);
                while (true) {
                    const bufToProcess = new Uint8Array(grpcBuffer, 0, used), bufLen = bufToProcess.byteLength;
                    offset = 0;
                    while (bufLen - offset >= 5) {
                        const grpcLen = ((bufToProcess[offset + 1] << 24) >>> 0) | (bufToProcess[offset + 2] << 16) | (bufToProcess[offset + 3] << 8) | bufToProcess[offset + 4];
                        const frameSize = 5 + grpcLen;
                        if (bufLen - offset >= frameSize) {
                            const grpcData = bufToProcess.subarray(offset + 5, offset + frameSize);
                            offset += frameSize;
                            let p = grpcData[0] === 0x0A ? 1 : 0;
                            while (p && grpcData[p++] & 0x80) ;
                            const payload = p === 0 ? grpcData : grpcData.subarray(p);
                            state.tcpWriter ? await state.tcpWriter(payload) : await handleSession(payload, state, request, writable, close);
                        } else {break}
                    }
                    if (offset < bufLen) {
                        used = bufLen - offset;
                        new Uint8Array(grpcBuffer).copyWithin(0, offset, bufLen);
                    } else {used = 0}
                    const {done, value} = await reader.read(new Uint8Array(grpcBuffer, used, 8192));
                    if (done) break;
                    grpcBuffer = value.buffer;
                    used += value.byteLength;
                }
            })().finally(() => close());
        },
        cancel() {state.tcpSocket?.close(), reader.releaseLock()}
    }), {headers: grpcHeaders});
};
const handleXhttpPost = async (request, reader, xhttpBuffer, used) => {
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, needMore: false, allowNeedMore: true, disableSsAead: true};
    return new Response(new ReadableStream({
        start(controller) {
            const writable = {send: (chunk) => controller.enqueue(chunk)};
            const close = () => {reader.releaseLock(), state.tcpSocket?.close(), controller.close()};
            (async () => {
                while (true) {
                    if (used > 0) {
                        const payload = new Uint8Array(xhttpBuffer, 0, used);
                        state.tcpWriter ? await state.tcpWriter(payload) : (state.needMore = false, await handleSession(payload, state, request, writable, close));
                        if (!state.needMore) {
                            used = 0;
                            continue;
                        }
                    }
                    const {done, value} = await reader.read(new Uint8Array(xhttpBuffer, used, used === 0 ? 8192 : 4096));
                    if (done) break;
                    xhttpBuffer = value.buffer;
                    used += value.byteLength;
                }
            })().finally(() => close());
        },
        cancel() {state.tcpSocket?.close(), reader.releaseLock()}
    }), {headers: xhttpHeaders});
};
const getErrorResponse = async (status = 200) => {
    if (!rawErrorHtml) rawErrorHtml = await decompressWasm(getErrorHtmlPtr, getErrorHtmlLen);
    return new Response(rawErrorHtml, {status, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
};
const getSub = async (request, url, uuid) => {
    if (uuid && url.searchParams.get('uuid') !== uuid) return await getErrorResponse(404);
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const proxyPath = url.searchParams.get('path') || '';
    const host = url.hostname;
    const hasVL = url.searchParams.get('vl') === '1';
    const hasTR = url.searchParams.get('tj') === '1';
    const hasWS = url.searchParams.get('ws') === '1';
    const hasXhttp = url.searchParams.get('xhttp') === '1';
    const hasGRPC = url.searchParams.get('grpc') === '1';
    const hasECH = url.searchParams.get('ech') === '1';
    const encPath = encodeURIComponent(proxyPath);
    const parts = [];
    const processTemplate = (index) => {
        if (cachedTemplates[index]) {
            const tmpl = cachedTemplates[index].replaceAll("{{HOST}}", host).replaceAll("{{PATH}}", encPath);
            ipListAll.forEach(entry => {
                const node = parseSubNode(entry);
                if (!node) return;
                parts.push(tmpl.replaceAll("{{IP}}", node.ip).replaceAll("{{port}}", node.port).replaceAll("{{name}}", node.name));
            });
        }
    };
    const addNodes = (base) => {
        if (hasWS) processTemplate(base + (hasECH ? 1 : 0));
        if (hasXhttp) processTemplate(base + (hasECH ? 3 : 2));
        if (hasGRPC) processTemplate(base + (hasECH ? 5 : 4));
    };
    if (hasVL) addNodes(0);
    if (hasTR) addNodes(6);
    const finalLinks = parts.join("\n");
    const base64Links = btoa(unescape(encodeURIComponent(finalLinks)));
    if (ua.includes(strList[18])) return new Response(base64Links, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
    if (url.searchParams.get('format') === 'raw') return new Response(finalLinks, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
    const target = (url.searchParams.has(strList[5]) || ua.includes(strList[5]) || ua.includes(strList[15]) || ua.includes(strList[16])) ? strList[5]
        : (url.searchParams.has(strList[11]) || url.searchParams.has(strList[6]) || ua.includes(strList[12]) || ua.includes(strList[6])) ? strList[6]
            : (url.searchParams.has(strList[13]) || ua.includes(strList[13])) ? strList[7]
                : (url.searchParams.has(strList[8]) || ua.includes(strList[14])) ? strList[8]
                    : (url.searchParams.has(strList[9]) || ua.includes(strList[9])) ? strList[9]
                        : (url.searchParams.has(strList[10]) || ua.includes(strList[10])) ? strList[10] : '';
    if (target) {
        const baseUrl = `${url.protocol}//${url.host}${url.pathname}?uuid=${globalThis.subUuid}&format=raw&path=${encPath}&vl=${hasVL ? 1 : 0}&tj=${hasTR ? 1 : 0}&ws=${hasWS ? 1 : 0}&xhttp=${hasXhttp ? 1 : 0}&grpc=${hasGRPC ? 1 : 0}`;
        const convertUrl = `${strList[0]}/sub?target=${target}&url=${encodeURIComponent(baseUrl)}&insert=false&config=${encodeURIComponent(strList[1])}&emoji=true&scv=true`;
        try {
            const response = await fetch(convertUrl, {
                headers: {'User-Agent': strList[19] + ' for ' + target + ' ' + userAgentSuffix}
            });
            if (response.ok) {
                return new Response(await response.text(), {
                    headers: {
                        'Content-Type': target === strList[5] ? 'application/x-yaml; charset=utf-8' : 'text/plain; charset=utf-8',
                        'Content-Disposition': `attachment; filename*=utf-8''${encodeURIComponent(strList[17])}`,
                        'Subscription-Userinfo': 'upload=0; download=0; total=1125899906842624; expire=253402271999',
                        'Profile-Update-Interval': '6'
                    }
                });
            }
        } catch {}
    }
    return new Response(base64Links, {headers: {'Content-Type': 'text/plain; charset=utf-8', 'Subscription-Userinfo': 'upload=0; download=0; total=1125899906842624; expire=253402271999'}});
};
export default {
    async fetch(request, env) {
        if (!isInitialized) initializeWasm(env);
        if (request.method === 'POST' && request.headers.get('content-type') === 'application/grpc-web') {
            const reader = request.body?.getReader({mode: 'byob'});
            if (!reader) return new Response(null, {status: 400});
            let postBuffer = new ArrayBuffer(8192), used = 0, buffer = new Uint8Array();
            while (buffer.length === 0 || (buffer[0] === 0 && buffer.length < 6)) {
                const {done, value} = await reader.read(new Uint8Array(postBuffer, used, 4096));
                if (done || !value?.byteLength) break;
                postBuffer = value.buffer;
                used += value.byteLength;
                buffer = new Uint8Array(postBuffer, 0, used);
            }
            if (buffer.length === 0) {
                reader.releaseLock();
                return new Response(null, {status: 400});
            }
            const isGrpc = !request.headers.get('Referer') && buffer.length >= 6 && buffer[0] === 0 && buffer[5] === 0x0A;
            return isGrpc ? handleGrpcPost(request, reader, buffer, used) : handleXhttpPost(request, reader, postBuffer, used);
        }
        if (request.headers.get('Upgrade') === 'websocket') {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair();
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        const url = new URL(request.url);
        const {uuid, password, user, pass, sspass} = getEnv(env);
        if (url.pathname === '/sub') return await getSub(request, url, uuid);
        if (url.pathname === `/${uuid}` || url.pathname === `/${password}`) {
            if (!rawHtml) {
                rawHtml = await decompressWasm(getPanelHtmlPtr, getPanelHtmlLen);
                const map = {UUID: uuid, PASS: password, HTTPPASS: `${user}:${pass}`, SSPASS: sspass, IPLIST: JSON.stringify(ipListAll), ECHDNS: encodeURIComponent(sharedEchDns)};
                rawHtml = rawHtml.replace(/{{(UUID|PASS|HTTPPASS|SSPASS|IPLIST|ECHDNS)}}/g, (_, k) => map[k]);
            }
            return new Response(rawHtml, {headers: {'Content-Type': 'text/html; charset=UTF-8'}});
        }
        return await getErrorResponse();
    }
};
