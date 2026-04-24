import {connect} from 'cloudflare:sockets';
const httpUser = 'admin';
const httpPass = '123456';
const bufferSize = 512 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 20;
const proxyStrategyOrder = ['socks', 'http'];
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
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
const [textEncoder, textDecoder, socks5Init] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
let httpAuthValue;
const httpRes200 = textEncoder.encode("HTTP/1.1 200 Connection Established\r\n\r\n"), httpRes407 = textEncoder.encode("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
if (httpUser && httpPass) httpAuthValue = textEncoder.encode(btoa(`${httpUser}:${httpPass}`));
const html = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
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
const createConnect = (hostname, port, socket = connect({hostname, port})) => socket.opened.then(() => socket);
const connectViaSocksProxy = async (targetPortNum, socksAuth, addrBytes) => {
    const socksSocket = await createConnect(socksAuth.hostname, socksAuth.port);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    await writer.write(socks5Init);
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
    const socksReq = new Uint8Array(7 + addrBytes.length);
    socksReq[0] = 5, socksReq[1] = 1, socksReq[2] = 0, socksReq[3] = 3;
    socksReq[4] = addrBytes.length, socksReq.set(addrBytes, 5);
    socksReq[socksReq.length - 2] = targetPortNum >> 8, socksReq[socksReq.length - 1] = targetPortNum & 0xff;
    await writer.write(socksReq);
    const {value: finalResponse} = await reader.read();
    if (!finalResponse || finalResponse[1] !== 0) return null;
    writer.releaseLock(), reader.releaseLock();
    return socksSocket;
};
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetPortNum, httpAuth, addrBytes) => {
    const {username, password, hostname, port} = httpAuth;
    const proxySocket = await createConnect(hostname, port);
    const writer = proxySocket.writable.getWriter();
    const httpHost = textDecoder.decode(addrBytes);
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
const parseHttp = (firstChunk) => {
    const len = firstChunk.length;
    if (len < 24 || firstChunk[len - 4] !== 13 || firstChunk[len - 3] !== 10 || firstChunk[len - 2] !== 13 || firstChunk[len - 1] !== 10) return null;
    const secondSpace = firstChunk.indexOf(32, 13);
    if (secondSpace === -1) return null;
    if (httpAuthValue) {
        let p = firstChunk.indexOf(66, secondSpace + 30), match = false;
        while (p !== -1 && p <= len - httpAuthValue.length - 10) {
            if (firstChunk[p + 1] === 97 && firstChunk[p + 2] === 115 && firstChunk[p + 3] === 105 && firstChunk[p + 4] === 99 && firstChunk[p + 5] === 32) {
                match = true;
                for (let j = 0; j < httpAuthValue.length; j++) if (firstChunk[p + 6 + j] !== httpAuthValue[j]) {
                    match = false;
                    break;
                }
                if (match) break;
            }
            p = firstChunk.indexOf(66, p + 1);
        }
        if (!match) return {authFailed: true};
    }
    const lastColon = firstChunk.lastIndexOf(58, secondSpace - 3);
    if (lastColon < 12) return null;
    let port = 0;
    for (let i = lastColon + 1, digit; i < secondSpace && (digit = firstChunk[i] - 48) >= 0 && digit <= 9; i++) port = port * 10 + digit;
    return {addrBytes: firstChunk.subarray(8, lastColon), port, dataOffset: len};
};
const strategyExecutorMap = new Map([
    [0, async ({port, addrBytes}) => {
        const hostname = textDecoder.decode(addrBytes);
        return createConnect(hostname, port);
    }],
    [1, async ({port, addrBytes}, param) => {
        const socksAuth = parseAuthString(param);
        return connectViaSocksProxy(port, socksAuth, addrBytes);
    }],
    [2, async ({port, addrBytes}, param) => {
        const httpAuth = parseAuthString(param);
        return connectViaHttpProxy(port, httpAuth, addrBytes);
    }],
    [3, async (_parsedRequest, param) => {
        const [host, port] = parseHostPort(param, 443);
        return createConnect(host, port);
    }]
]);
const paramRegex = /(gs5|s5all|ghttp|httpall|s5|socks|http|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), list = [];
    if (clean.length < 6) {list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US})} else {
        paramRegex.lastIndex = 0;
        let m, p = Object.create(null);
        while ((m = paramRegex.exec(clean))) p[(m[1] || m[3]).toLowerCase()] = m[2] ? (m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2]) : true;
        const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http;
        const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.proxyall || p.globalproxy);
        if (!proxyAll) list.push({type: 0});
        const add = (v, t) => {
            if (!v) return;
            const parts = decodeURIComponent(v).split(',');
            for (let i = 0; i < parts.length; i++) if (parts[i]) list.push({type: t, param: parts[i]});
        };
        for (let i = 0; i < proxyStrategyOrder.length; i++) {
            const k = proxyStrategyOrder[i];
            k === 'socks' ? add(s5, 1) : k === 'http' ? add(http, 2) : 0;
        }
        if (proxyAll) {if (!list.length) list.push({type: 0})} else {
            add(p.ip, 3);
            list.push({type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US});
        }
    }
    for (let i = 0; i < list.length; i++) {
        try {
            const socket = await strategyExecutorMap.get(list[i].type)?.(parsedRequest, list[i].param);
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
const manualPipe = async (readable, writable) => {
    const safeBufferSize = bufferSize - maxChunkLen;
    let buffer = new Uint8Array(bufferSize), chunkBuf = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, time = 2, timerId = null, resume = null;
    let globalCount = new Float64Array(14), globalBytes = new Float64Array(14);
    let statCount = 0, totalCount = 0, totalGlobalBytes = 0;
    const flushBuffer = () => {
        offset > 0 && (writable.send(buffer.slice(0, offset)), offset = 0);
        timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const {done, value} = await reader.read(new Uint8Array(chunkBuf));
            if (done) break;
            chunkBuf = value.buffer;
            const chunkLen = value.byteLength, idx = chunkLen >= 30720 ? 13 : chunkIdxLookup[chunkLen >> 9];
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
const handleWebSocketConn = async (webSocket, request) => {
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const earlyData = protocolHeader ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    let tcpWrite, processingChain = Promise.resolve(), parsedRequest, tcpSocket;
    const closeSocket = () => {if (!earlyData) {tcpSocket?.close(), webSocket?.close()}};
    const processMessage = async (chunk) => {
        try {
            if (tcpWrite) return tcpWrite(chunk);
            chunk = earlyData ? chunk : new Uint8Array(chunk);
            parsedRequest = parseHttp(chunk);
            if (parsedRequest?.authFailed) {
                webSocket.send(httpRes407);
                return closeSocket();
            }
            if (!parsedRequest) return closeSocket();
            webSocket.send(httpRes200);
            const payload = chunk.subarray(parsedRequest.dataOffset);
            tcpSocket = await establishTcpConnection(parsedRequest, request);
            if (!tcpSocket) return closeSocket();
            const tcpWriter = tcpSocket.writable.getWriter();
            if (payload.byteLength) tcpWriter.write(payload);
            tcpWrite = (chunk) => tcpWriter.write(chunk);
            manualPipe(tcpSocket.readable, webSocket);
        } catch {closeSocket()}
    };
    if (earlyData) processingChain = processingChain.then(() => processMessage(earlyData));
    webSocket.addEventListener("message", event => processingChain = processingChain.then(() => processMessage(event.data)));
};
export default {
    async fetch(request) {
        if (request.headers.get('Upgrade') === 'websocket') {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair();
            // @ts-ignore
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        return new Response(html, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};