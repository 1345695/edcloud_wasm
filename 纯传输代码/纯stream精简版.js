import {connect as c} from 'cloudflare:sockets';
const p = {EU: 'proxyip.de.cmliussss.net', AS: 'proxyip.sg.cmliussss.net', JP: 'proxyip.jp.cmliussss.net', US: 'proxyip.us.cmliussss.net'};
const r = {JP: new Set(['ICN', 'KIX', 'NRT']), EU: new Set(['FRA', 'HAM', 'MRS', 'CDG', 'LHR']), AS: new Set(['HKG', 'SIN', 'TPE'])};
const m = new Map(Object.entries(r).flatMap(([g, o]) => Array.from(o, l => [l, p[g]])));
const d = new TextDecoder();
const f = (h, p, s = c({hostname: h, port: p})) => s.opened.then(() => s);
const h = async (w, q) => {
    const a = q.headers.get('sec-websocket-protocol');
    const e = a ? Uint8Array.fromBase64(a, {alphabet: 'base64url'}) : null;
    const s = new ReadableStream({
        start(c) {
            if (e) c.enqueue(e);
            w.addEventListener("message", v => c.enqueue(v.data))
        }, cancel() {w?.close()}
    });
    let g, t;
    s.pipeTo(new WritableStream({
        async write(k) {
            if (g) return g(k);
            k = e ? k : new Uint8Array(k);
            w.send(new Uint8Array([k[0], 0]));
            let o = 19 + k[17];
            const r = (k[o] << 8) | k[o + 1];
            o += 2;
            const y = k[o++];
            let n, b;
            if (y === 2) {
                const l = k[o++];
                n = o + l;
                b = d.decode(k.subarray(o, n))
            } else if (y === 1) {
                n = o + 4;
                const z = k.subarray(o, n);
                b = `${z[0]}.${z[1]}.${z[2]}.${z[3]}`
            } else if (y === 3) {
                n = o + 16;
                let i = ((k[o] << 8) | k[o + 1]).toString(16);
                for (let j = 1; j < 8; j++) i += ':' + ((k[o + j * 2] << 8) | k[o + j * 2 + 1]).toString(16);
                b = `[${i}]`
            }
            t = await f(b, r).catch(() => {
                const u = new URL(q.url);
                const x = u.searchParams.get('ip') ?? m.get(q.cf?.colo) ?? p.US;
                const [s, w = r] = x.split(":");
                return f(s, w)
            });
            const j = t.writable.getWriter();
            const l = k.subarray(n);
            if (l.byteLength) j.write(l);
            g = (k) => j.write(k);
            t.readable.pipeTo(new WritableStream({write(k) {w.send(k)}}))
        }
    })).finally(() => {t?.close(), w?.close()})
};
export default {
    async fetch(q) {
        if (q.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
            const {0: a, 1: b} = new WebSocketPair();
            b.accept({allowHalfOpen: true}), b.binaryType = "arraybuffer";
            h(b, q);
            return new Response(null, {status: 101, webSocket: a})
        } else {return new Response(null, {status: 400})}
    }
};