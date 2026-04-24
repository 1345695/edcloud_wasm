import {connect} from 'cloudflare:sockets';
const bufferSize = 512 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 20;
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const coloRegions = {JP: new Set(['ICN', 'KIX', 'NRT']), EU: new Set(['FRA', 'HAM', 'MRS', 'CDG', 'LHR']), AS: new Set(['HKG', 'SIN', 'TPE'])};
const coloToProxyMap = new Map();
for (const [region, colos] of Object.entries(coloRegions)) {for (const colo of colos) coloToProxyMap.set(colo, proxyIpAddrs[region])}
const textDecoder = new TextDecoder();
const createConnect = (hostname, port, socket = connect({hostname, port})) => socket.opened.then(() => socket);
const concurrentConnect = (hostname, port) => Promise.any(Array(4).fill().map(() => createConnect(hostname, port)));
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
    let tcpWrite, processingChain = Promise.resolve(), tcpSocket;
    const closeSocket = () => {if (!earlyData) {tcpSocket?.close(), webSocket?.close()}};
    const processMessage = async (chunk) => {
        try {
            if (tcpWrite) return tcpWrite(chunk);
            chunk = earlyData ? chunk : new Uint8Array(chunk);
            webSocket.send(new Uint8Array([chunk[0], 0]));
            let offset = 19 + chunk[17];
            const port = (chunk[offset] << 8) | chunk[offset + 1];
            offset += 2;
            const addrType = chunk[offset++];
            let newOffset, hostname;
            if (addrType === 2) {
                const len = chunk[offset++];
                newOffset = offset + len;
                hostname = textDecoder.decode(chunk.subarray(offset, newOffset));
            } else if (addrType === 1) {
                newOffset = offset + 4;
                const bytes = chunk.subarray(offset, newOffset);
                hostname = `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
            } else {
                newOffset = offset + 16;
                let ipv6Str = ((chunk[offset] << 8) | chunk[offset + 1]).toString(16);
                for (let i = 1; i < 8; i++) ipv6Str += ':' + ((chunk[offset + i * 2] << 8) | chunk[offset + i * 2 + 1]).toString(16);
                hostname = `[${ipv6Str}]`;
            }
            tcpSocket = await concurrentConnect(hostname, port).catch(() => {
                const url = new URL(request.url);
                const proxyHost = url.searchParams.get('proxyip') ?? coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US;
                return concurrentConnect(proxyHost, 443);
            });
            const tcpWriter = tcpSocket.writable.getWriter();
            const payload = chunk.subarray(newOffset);
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
        } else {return new Response(null, {status: 400})}
    }
};