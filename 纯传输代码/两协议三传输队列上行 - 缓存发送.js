import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥计算网址：https://www.lzltool.com/data-sha224
const passWordSha224 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const bufferSize = 512 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 20;
let concurrency = 4;
const urlParamCacheLimit = 20;
const proxyStrategyOrder = ['socks', 'http'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const finallyProxyHost = 'ProxyIP.CMLiussss.net';
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
const uuidBytes = new Uint8Array(16), hashBytes = new Uint8Array(56), offsets = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let i = 0, c; i < 16; i++) uuidBytes[i] = (((c = uuid.charCodeAt(i * 2 + offsets[i])) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = uuid.charCodeAt(i * 2 + offsets[i] + 1)) > 64 ? c + 9 : c) & 0xF);
for (let i = 0; i < 56; i++) hashBytes[i] = passWordSha224.charCodeAt(i);
const [textEncoder, textDecoder, socks5Init] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
const html = `<body style=margin:0;overflow:hidden;background:#000><canvas id=c style=width:100vw;height:100vh><script>var C=document.getElementById("c"),g=C.getContext("webgl"),t=0,P,R,F,U,O,X,Y,L,T,b=.4,K="float L(vec3 v){vec3 a=v;float b,c,d;for(int i=0;i<5;i++){b=length(a);c=atan(a.y,a.x)*10.;d=acos(a.z/b)*10.;b=pow(b,8.);a=vec3(b*sin(d)*cos(c),b*sin(d)*sin(c),b*cos(d))+v;if(b>6.)break;}return 4.-dot(a,a);}",VS="attribute vec4 p;varying vec3 d,ld;uniform vec3 r,f,u;uniform float x,y;void main(){gl_Position=p;d=f+r*p.x*x+u*p.y*y;ld=vec3(p.x*x,p.y*y,-1.);}",FS="precision highp float;float L(vec3 v);uniform vec3 r,f,u,o;uniform float t;varying vec3 d,ld;uniform float l;void main(){vec3 tc=vec3(0);for(int i=0;i<4;i++){vec2 of=vec2(mod(float(i),2.),floor(float(i)/2.))*.5;vec3 rd=normalize(d+r*of.x*.001+u*of.y*.001),c=vec3(0);float s=.002*l,r1,r2,r3;for(int k=2;k<1200;k++){float ds=s*float(k);vec3 p=o+rd*ds;if(L(p)>0.){r1=s*float(k-1);r2=ds;for(int j=0;j<24;j++){r3=(r1+r2)*.5;if(L(o+rd*r3)>0.)r2=r3;else r1=r3;}vec3 v=o+rd*r3,nw;float e=r3*1e-4;nw=normalize(vec3(L(v-r*e)-L(v+r*e),L(v-u*e)-L(v+u*e),L(v+f*e)-L(v-f*e)));vec3 rf=reflect(normalize(ld),nw);float d2=dot(v,v),lt=pow(max(0.,dot(rf,vec3(.276,.92,.276))),4.)*.45+max(0.,dot(nw,vec3(.276,.92,.276)))*.25+.3;c=(sin(d2*5.+t+vec3(0,2,4))*.5+.5)*lt;break;}}tc+=c;}gl_FragColor=vec4(pow(tc*.25,vec3(.7)),1);}";function i(){var s=g.createProgram(),v=g.createShader(35633),f=g.createShader(35632);g.shaderSource(v,VS),g.compileShader(v),g.shaderSource(f,FS+K),g.compileShader(f),g.attachShader(s,v),g.attachShader(s,f),g.linkProgram(s),g.useProgram(s),P=g.getAttribLocation(s,"p"),R=g.getUniformLocation(s,"r"),F=g.getUniformLocation(s,"f"),U=g.getUniformLocation(s,"u"),O=g.getUniformLocation(s,"o"),X=g.getUniformLocation(s,"x"),Y=g.getUniformLocation(s,"y"),L=g.getUniformLocation(s,"l"),T=g.getUniformLocation(s,"t"),g.bindBuffer(34962,g.createBuffer()),g.bufferData(34962,new Float32Array([-1,-1,0,1,-1,0,1,1,0,-1,-1,0,1,1,0,-1,1,0]),35044),g.vertexAttribPointer(P,3,5126,!1,0,0),g.enableVertexAttribArray(P)}function w(){t+=.02,innerWidth*devicePixelRatio!=C.width&&(C.width=innerWidth*(d=devicePixelRatio||1),C.height=innerHeight*d,g.viewport(0,0,C.width,C.height));var v=C.width/C.height;g.uniform1f(X,v>1?v:1),g.uniform1f(Y,v>1?1:1/v),g.uniform1f(L,1.6),g.uniform1f(T,t),g.uniform3f(O,1.6*Math.cos(t*.5)*Math.cos(b),1.6*Math.sin(b),1.6*Math.sin(t*.5)*Math.cos(b)),g.uniform3f(R,Math.sin(t*.5),0,-Math.cos(t*.5)),g.uniform3f(U,-Math.sin(b)*Math.cos(t*.5),Math.cos(b),-Math.sin(b)*Math.sin(t*.5)),g.uniform3f(F,-Math.cos(t*.5)*Math.cos(b),-Math.sin(b),-Math.sin(t*.5)*Math.cos(b)),g.drawArrays(4,0,6),requestAnimationFrame(w)}i(),w()</script>`;
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`;
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
const concurrentConnect = (hostname, port, limit = concurrency) => {
    if (limit === 1) return createConnect(hostname, port);
    return Promise.any(Array(limit).fill(null).map(() => createConnect(hostname, port)));
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes, limit) => {
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, limit);
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
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, limit) => {
    const {username, password, hostname, port} = httpAuth;
    const proxySocket = await concurrentConnect(hostname, port, limit);
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
const parseProtocolChunk = (chunk) => {
    const len = chunk.length;
    const result = {success: false, needMore: false, handshake: null, parsedRequest: null};
    let isVL = false;
    if (len >= 17) {
        isVL = true;
        for (let i = 0; i < 16; i++) {
            if (chunk[i + 1] !== uuidBytes[i]) {
                isVL = false;
                break;
            }
        }
    }
    if (isVL) {
        if (len < 18) return result.needMore = true, result;
        const offset = 19 + chunk[17];
        if (len < offset + 4) return result.needMore = true, result;
        let addrType = chunk[offset + 2];
        if (addrType !== 1) addrType += 1;
        const addrLen = addrType === 3 ? (offset + 3 < len ? chunk[offset + 3] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            const addrOffset = addrType === 3 ? offset + 4 : offset + 3;
            const dataOffset = addrOffset + addrLen;
            if (len < dataOffset) return result.needMore = true, result;
            const port = (chunk[offset] << 8) | chunk[offset + 1];
            result.handshake = new Uint8Array([chunk[0], 0]);
            result.success = true;
            result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    if (len >= 56) {
        let isTJ = true;
        for (let i = 0; i < 56; i++) {
            if (chunk[i] !== hashBytes[i]) {
                isTJ = false;
                break;
            }
        }
        if (isTJ) {
            if (len < 60) return result.needMore = true, result;
            const addrType = chunk[59];
            const addrLen = addrType === 3 ? (60 < len ? chunk[60] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
            if (addrLen === null) return result.needMore = true, result;
            if (addrLen > 0) {
                const addrOffset = addrType === 3 ? 61 : 60;
                const dataOffset = addrOffset + addrLen + 4;
                if (len < dataOffset) return result.needMore = true, result;
                const portOffset = addrOffset + addrLen;
                const port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
                result.success = true;
                result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
                return result;
            }
        }
    }
    return len < 56 ? (result.needMore = true, result) : result;
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
    [3, async (_parsedRequest, param, limit) => {
        return connectProxyIp(param, limit);
    }]
]);
const paramRegex = /(gs5|s5all|ghttp|httpall|s5|socks|http|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const urlListCacheDict = Object.create(null), urlListCacheKeys = new Array(urlParamCacheLimit);
let urlListCacheIndex = 0;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), l = clean.length, list = [];
    const c = clean.charCodeAt(l - 1);
    if (c === 47 || c === 61) clean = clean.slice(0, l - 1);
    const cachedList = urlListCacheDict[clean];
    if (cachedList !== undefined) {
        list = cachedList;
    } else {
        if (clean.length < 6) {
            list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
        } else {
            const p = Object.create(null);
            paramRegex.lastIndex = 0;
            let m;
            while ((m = paramRegex.exec(clean))) {p[(m[1] || m[3]).toLowerCase()] = m[2] ? (m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2]) : true}
            const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http;
            const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.proxyall || p.globalproxy);
            if (!proxyAll) list.push({type: 0});
            const add = (v, t) => {
                if (!v) return;
                const parts = decodeURIComponent(v).split(',').filter(Boolean);
                if (parts.length) {
                    const parsedParams = parts.map(part => {
                        if (t === 1 || t === 2) return parseAuthString(part);
                        return part;
                    });
                    list.push({type: t, param: parsedParams, concurrent: true});
                }
            };
            for (let i = 0; i < proxyStrategyOrder.length; i++) {
                const k = proxyStrategyOrder[i];
                add(k === 'socks' ? s5 : http, k === 'socks' ? 1 : 2);
            }
            if (proxyAll) {
                if (!list.length) list.push({type: 0});
            } else {
                add(p.ip, 3);
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
            const sub = (list[i]['concurrent'] && Array.isArray(list[i].param)) ? Math.max(1, Math.floor(concurrency / list[i].param.length)) : undefined;
            const socket = await (list[i]['concurrent'] && Array.isArray(list[i].param) ? Promise.any(list[i].param.map(ip => exec(parsedRequest, ip, sub))) : exec(parsedRequest, list[i].param));
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
const handleSession = async (chunk, state, request, writable, close) => {
    state.needMore = false;
    const parsed = parseProtocolChunk(chunk);
    parsed.handshake && writable.send(parsed.handshake);
    if (!parsed.success) return parsed.needMore ? (state.needMore = true) : close();
    const parsedRequest = parsed.parsedRequest;
    const payload = chunk.subarray(parsedRequest.dataOffset);
    if (parsedRequest.isDns) {
        const dnsPack = await dohDnsHandler(payload);
        if (dnsPack?.byteLength) writable.send(dnsPack);
        return close();
    } else {
        state.tcpSocket = await establishTcpConnection(parsedRequest, request);
        if (!state.tcpSocket) return close();
        const tcpWriter = state.tcpSocket.writable.getWriter();
        if (payload.byteLength) await tcpWriter.write(payload);
        state.tcpWriter = (c) => tcpWriter.write(c);
        if (state.tcpSocket.extra?.length) writable.send(state.tcpSocket.extra);
        manualPipe(state.tcpSocket.readable, writable).finally(() => close());
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const earlyData = protocolHeader ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
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
    const state = {tcpWriter: null, tcpSocket: null};
    return new Response(new ReadableStream({
        start(controller) {
            const writable = {
                send: (chunk) => {
                    const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                    const len = data.byteLength;
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
                    grpcFrame.set(data, p);
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
                            state.tcpWriter ? state.tcpWriter(payload) : await handleSession(payload, state, request, writable, close);
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
    const state = {tcpWriter: null, tcpSocket: null, needMore: false};
    return new Response(new ReadableStream({
        start(controller) {
            const writable = {send: (chunk) => controller.enqueue(chunk)};
            const close = () => {reader.releaseLock(), state.tcpSocket?.close(), controller.close()};
            (async () => {
                while (true) {
                    if (used > 0) {
                        const payload = new Uint8Array(xhttpBuffer, 0, used);
                        state.tcpWriter ? state.tcpWriter(payload) : (state.needMore = false, await handleSession(payload, state, request, writable, close));
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
export default {
    async fetch(request) {
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
            // @ts-ignore
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        return new Response(html, {status: 200, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};
