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
const manualPipe = async (readable, writable) => {
    const _bufferSize = bufferSize, _maxChunkLen = maxChunkLen, _startThreshold = startThreshold, _flushTime = flushTime, _safeBufferSize = _bufferSize - _maxChunkLen;
    let mainBuf = new ArrayBuffer(_bufferSize), offset = 0, time = 2, timerId = null, resume = null, isReading = false, needsFlush = false, totalBytes = 0;
    const flush = () => {
        if (isReading) return needsFlush = true;
        offset > 0 && (writable.send(mainBuf.slice(0, offset)), offset = 0);
        needsFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            isReading = true;
            const {done, value} = await reader.read(new Uint8Array(mainBuf, offset, _maxChunkLen));
            if (isReading = false, done) break;
            mainBuf = value.buffer;
            const chunkLen = value.byteLength;
            if (chunkLen < _maxChunkLen) {
                time = 2, chunkLen < 4096 && (totalBytes = 0);
                offset > 0 ? (offset += chunkLen, flush()) : writable.send(value.slice());
            } else {
                totalBytes += chunkLen;
                offset += chunkLen, timerId ||= setTimeout(flush, time), needsFlush && flush();
                offset > _safeBufferSize && (totalBytes > _startThreshold && (time = _flushTime), await new Promise(r => resume = r));
            }
        }
    } finally {isReading = false, flush(), reader.releaseLock()}
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
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        } else {return new Response(null, {status: 400})}
    }
};