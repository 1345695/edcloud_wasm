import {connect as 建立雲端連線} from 'cloudflare:sockets';
const 使用者識別碼 = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const 密碼雜湊值 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const 緩衝區大小 = 512 * 1024;
const 啟動閾值 = 50 * 1024 * 1024;
const 最大區塊長度 = 64 * 1024;
const 刷新時間 = 20;
const 代理策略順序 = ['socks', 'http'];
const 代理位址表 = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const 機房區域對照 = {
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
const 機房到代理映射 = new Map();
for (const [區域代號, 機房集合] of Object.entries(機房區域對照)) {for (const 機房代號 of 機房集合) 機房到代理映射.set(機房代號, 代理位址表[區域代號])}
const 識別碼位元組 = new Uint8Array(16), 雜湊位元組 = new Uint8Array(56), 偏移陣列 = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let 索引 = 0, 暫存值; 索引 < 16; 索引++) 識別碼位元組[索引] = (((暫存值 = 使用者識別碼.charCodeAt(索引 * 2 + 偏移陣列[索引])) > 64 ? 暫存值 + 9 : 暫存值) & 0xF) << 4 | (((暫存值 = 使用者識別碼.charCodeAt(索引 * 2 + 偏移陣列[索引] + 1)) > 64 ? 暫存值 + 9 : 暫存值) & 0xF);
for (let 索引 = 0; 索引 < 56; 索引++) 雜湊位元組[索引] = 密碼雜湊值.charCodeAt(索引);
const [文字編碼器, 文字解碼器, 通道五初始化封包] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
const 錯誤網頁內容 = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const 二進位位址轉字串 = (位址類型, 位址位元組) => {
    if (位址類型 === 3) return 文字解碼器.decode(位址位元組);
    if (位址類型 === 1) return `${位址位元組[0]}.${位址位元組[1]}.${位址位元組[2]}.${位址位元組[3]}`;
    let 第六版位址字串 = ((位址位元組[0] << 8) | 位址位元組[1]).toString(16);
    for (let 索引 = 1; 索引 < 8; 索引++) 第六版位址字串 += ':' + ((位址位元組[索引 * 2] << 8) | 位址位元組[索引 * 2 + 1]).toString(16);
    return `[${第六版位址字串}]`;
};
const 解析主機連接埠 = (位址字串, 預設連接埠) => {
    let 主機 = 位址字串, 連接埠 = 預設連接埠, 索引位置;
    if (位址字串.charCodeAt(0) === 91) {
        if ((索引位置 = 位址字串.indexOf(']:')) !== -1) {
            主機 = 位址字串.substring(0, 索引位置 + 1);
            連接埠 = 位址字串.substring(索引位置 + 2);
        }
    } else if ((索引位置 = 位址字串.indexOf('.tp')) !== -1 && 位址字串.lastIndexOf(':') === -1) {
        連接埠 = 位址字串.substring(索引位置 + 3, 位址字串.indexOf('.', 索引位置 + 3));
    } else if ((索引位置 = 位址字串.lastIndexOf(':')) !== -1) {
        主機 = 位址字串.substring(0, 索引位置);
        連接埠 = 位址字串.substring(索引位置 + 1);
    }
    return [主機, (連接埠 = parseInt(連接埠), isNaN(連接埠) ? 預設連接埠 : 連接埠)];
};
const 解析認證字串 = (認證參數) => {
    let 使用者名稱, 密碼, 主機字串;
    const 艾特位置 = 認證參數.lastIndexOf('@');
    if (艾特位置 === -1) {主機字串 = 認證參數} else {
        const 認證片段 = 認證參數.substring(0, 艾特位置);
        主機字串 = 認證參數.substring(艾特位置 + 1);
        const 冒號位置 = 認證片段.indexOf(':');
        if (冒號位置 === -1) {使用者名稱 = 認證片段} else {
            使用者名稱 = 認證片段.substring(0, 冒號位置);
            密碼 = 認證片段.substring(冒號位置 + 1);
        }
    }
    const [主機名稱, 連接埠] = 解析主機連接埠(主機字串, 1080);
    return {使用者名稱, 密碼, 主機名稱, 連接埠};
};
const 建立單次連線 = (主機名稱, 連接埠, 連線插槽 = 建立雲端連線({hostname: 主機名稱, port: 連接埠})) => 連線插槽.opened.then(() => 連線插槽);
const 經通道代理連線 = async (目標位址類型, 目標連接埠數值, 通道認證資訊, 位址位元組) => {
    const 通道連線插槽 = await 建立單次連線(通道認證資訊.主機名稱, 通道認證資訊.連接埠);
    const 寫入器 = 通道連線插槽.writable.getWriter();
    const 讀取器 = 通道連線插槽.readable.getReader();
    await 寫入器.write(通道五初始化封包);
    const {value: 認證回應} = await 讀取器.read();
    if (!認證回應 || 認證回應[0] !== 5 || 認證回應[1] === 0xFF) return null;
    if (認證回應[1] === 2) {
        if (!通道認證資訊.使用者名稱) return null;
        const 使用者位元組 = 文字編碼器.encode(通道認證資訊.使用者名稱);
        const 密碼位元組 = 文字編碼器.encode(通道認證資訊.密碼 || '');
        const 使用者長度 = 使用者位元組.length, 密碼長度 = 密碼位元組.length, 認證請求 = new Uint8Array(3 + 使用者長度 + 密碼長度)
        認證請求[0] = 1, 認證請求[1] = 使用者長度, 認證請求.set(使用者位元組, 2), 認證請求[2 + 使用者長度] = 密碼長度, 認證請求.set(密碼位元組, 3 + 使用者長度);
        await 寫入器.write(認證請求);
        const {value: 認證結果} = await 讀取器.read();
        if (!認證結果 || 認證結果[0] !== 1 || 認證結果[1] !== 0) return null;
    } else if (認證回應[1] !== 0) {return null}
    const 是否網域 = 目標位址類型 === 3, 通道請求封包 = new Uint8Array(6 + 位址位元組.length + (是否網域 ? 1 : 0));
    通道請求封包[0] = 5, 通道請求封包[1] = 1, 通道請求封包[2] = 0, 通道請求封包[3] = 目標位址類型;
    是否網域 ? (通道請求封包[4] = 位址位元組.length, 通道請求封包.set(位址位元組, 5)) : 通道請求封包.set(位址位元組, 4);
    通道請求封包[通道請求封包.length - 2] = 目標連接埠數值 >> 8, 通道請求封包[通道請求封包.length - 1] = 目標連接埠數值 & 0xff;
    await 寫入器.write(通道請求封包);
    const {value: 最終回應} = await 讀取器.read();
    if (!最終回應 || 最終回應[1] !== 0) return null;
    寫入器.releaseLock(), 讀取器.releaseLock();
    return 通道連線插槽;
};
const 固定超文本標頭 = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const 已編碼固定標頭 = 文字編碼器.encode(固定超文本標頭);
const 經超文本代理連線 = async (目標位址類型, 目標連接埠數值, 超文本認證資訊, 位址位元組) => {
    const {使用者名稱, 密碼, 主機名稱, 連接埠} = 超文本認證資訊;
    const 代理連線插槽 = await 建立單次連線(主機名稱, 連接埠);
    const 寫入器 = 代理連線插槽.writable.getWriter();
    const 超文本主機 = 二進位位址轉字串(目標位址類型, 位址位元組);
    let 動態標頭 = `CONNECT ${超文本主機}:${目標連接埠數值} HTTP/1.1\r\nHost: ${超文本主機}:${目標連接埠數值}\r\n`;
    if (使用者名稱) 動態標頭 += `Proxy-Authorization: Basic ${btoa(`${使用者名稱}:${密碼 || ''}`)}\r\n`;
    const 完整標頭 = new Uint8Array(動態標頭.length * 3 + 已編碼固定標頭.length);
    const {written: 已寫入長度} = 文字編碼器.encodeInto(動態標頭, 完整標頭);
    完整標頭.set(已編碼固定標頭, 已寫入長度);
    await 寫入器.write(完整標頭.subarray(0, 已寫入長度 + 已編碼固定標頭.length));
    寫入器.releaseLock();
    const 讀取器 = 代理連線插槽.readable.getReader();
    const 暫存緩衝區 = new Uint8Array(512);
    let 已讀位元組 = 0, 狀態已檢查 = false;
    while (已讀位元組 < 暫存緩衝區.length) {
        const {value: 讀取值, done: 是否完成} = await 讀取器.read();
        if (是否完成 || 已讀位元組 + 讀取值.length > 暫存緩衝區.length) return null;
        const 先前已讀位元組 = 已讀位元組;
        暫存緩衝區.set(讀取值, 已讀位元組);
        已讀位元組 += 讀取值.length;
        if (!狀態已檢查 && 已讀位元組 >= 12) {
            if (暫存緩衝區[9] !== 50) return null;
            狀態已檢查 = true;
        }
        let 索引 = Math.max(15, 先前已讀位元組 - 3);
        while ((索引 = 暫存緩衝區.indexOf(13, 索引)) !== -1 && 索引 <= 已讀位元組 - 4) {
            if (暫存緩衝區[索引 + 1] === 10 && 暫存緩衝區[索引 + 2] === 13 && 暫存緩衝區[索引 + 3] === 10) {
                讀取器.releaseLock();
                return 代理連線插槽;
            }
            索引++;
        }
    }
    return null;
};
const 解析位址資料 = (暫存緩衝區, 偏移量, 位址類型) => {
    const 位址長度 = 位址類型 === 3 ? 暫存緩衝區[偏移量++] : 位址類型 === 1 ? 4 : 位址類型 === 4 ? 16 : null;
    if (位址長度 === null) return null;
    const 資料偏移 = 偏移量 + 位址長度;
    if (資料偏移 > 暫存緩衝區.length) return null;
    const 位址位元組 = 暫存緩衝區.subarray(偏移量, 資料偏移);
    return {位址位元組, 資料偏移};
};
const 解析請求封包 = (首區塊) => {
    for (let 索引 = 0; 索引 < 16; 索引++) if (首區塊[索引 + 1] !== 識別碼位元組[索引]) return null;
    let 偏移量 = 19 + 首區塊[17];
    const 連接埠 = (首區塊[偏移量] << 8) | 首區塊[偏移量 + 1];
    let 位址類型 = 首區塊[偏移量 + 2];
    if (位址類型 !== 1) 位址類型 += 1;
    const 位址資訊 = 解析位址資料(首區塊, 偏移量 + 3, 位址類型);
    if (!位址資訊) return null;
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移, 連接埠};
};
const 解析透明代理封包 = (首區塊) => {
    for (let 索引 = 0; 索引 < 56; 索引++) if (首區塊[索引] !== 雜湊位元組[索引]) return null;
    const 位址類型 = 首區塊[59];
    const 位址資訊 = 解析位址資料(首區塊, 60, 位址類型);
    if (!位址資訊) return null;
    const 連接埠 = (首區塊[位址資訊.資料偏移] << 8) | 首區塊[位址資訊.資料偏移 + 1];
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移 + 4, 連接埠};
};
const 解析影子代理封包 = (首區塊) => {
    const 位址類型 = 首區塊[0];
    const 位址資訊 = 解析位址資料(首區塊, 1, 位址類型);
    if (!位址資訊) return null;
    const 連接埠 = (首區塊[位址資訊.資料偏移] << 8) | 首區塊[位址資訊.資料偏移 + 1];
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移 + 2, 連接埠};
};
const 策略執行器映射 = new Map([
    [0, async ({位址類型, 連接埠, 位址位元組}) => {
        const 主機名稱 = 二進位位址轉字串(位址類型, 位址位元組);
        return 建立單次連線(主機名稱, 連接埠);
    }],
    [1, async ({位址類型, 連接埠, 位址位元組}, 參數值) => {
        const 通道認證資訊 = 解析認證字串(參數值);
        return 經通道代理連線(位址類型, 連接埠, 通道認證資訊, 位址位元組);
    }],
    [2, async ({位址類型, 連接埠, 位址位元組}, 參數值) => {
        const 超文本認證資訊 = 解析認證字串(參數值);
        return 經超文本代理連線(位址類型, 連接埠, 超文本認證資訊, 位址位元組);
    }],
    [3, async (_已解析請求, 參數值) => {
        const [主機, 連接埠] = 解析主機連接埠(參數值, 443);
        return 建立單次連線(主機, 連接埠);
    }]
]);
const 參數匹配正則 = /(gs5|s5all|ghttp|httpall|s5|socks|http|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const 建立傳輸控制連線 = async (已解析請求, 請求) => {
    let 網址字串 = 請求.url, 清理路徑 = 網址字串.slice(網址字串.indexOf('/', 10) + 1), 策略列表 = [];
    if (清理路徑.length < 6) {策略列表.push({類型: 0}, {類型: 3, 參數: 機房到代理映射.get(請求.cf?.colo) ?? 代理位址表.US})} else {
        參數匹配正則.lastIndex = 0;
        let 匹配項, 暫指標 = Object.create(null);
        while ((匹配項 = 參數匹配正則.exec(清理路徑))) 暫指標[(匹配項[1] || 匹配項[3]).toLowerCase()] = 匹配項[2] ? (匹配項[2].charCodeAt(匹配項[2].length - 1) === 61 ? 匹配項[2].slice(0, -1) : 匹配項[2]) : true;
        const 通道設定 = 暫指標.gs5 || 暫指標.s5all || 暫指標.s5 || 暫指標.socks, 超文本設定 = 暫指標.ghttp || 暫指標.httpall || 暫指標.http;
        const 全域代理 = !!(暫指標.gs5 || 暫指標.s5all || 暫指標.ghttp || 暫指標.httpall || 暫指標.proxyall || 暫指標.globalproxy);
        if (!全域代理) 策略列表.push({類型: 0});
        const 加入策略 = (暫值, 類型值) => {
            if (!暫值) return;
            const 分段陣列 = decodeURIComponent(暫值).split(',');
            for (let 索引 = 0; 索引 < 分段陣列.length; 索引++) if (分段陣列[索引]) 策略列表.push({類型: 類型值, 參數: 分段陣列[索引]});
        };
        for (let 索引 = 0; 索引 < 代理策略順序.length; 索引++) {
            const 鍵索引 = 代理策略順序[索引];
            鍵索引 === 'socks' ? 加入策略(通道設定, 1) : 鍵索引 === 'http' ? 加入策略(超文本設定, 2) : 0;
        }
        if (全域代理) {if (!策略列表.length) 策略列表.push({類型: 0})} else {
            加入策略(暫指標.ip, 3);
            策略列表.push({類型: 3, 參數: 機房到代理映射.get(請求.cf?.colo) ?? 代理位址表.US});
        }
    }
    for (let 索引 = 0; 索引 < 策略列表.length; 索引++) {
        try {
            const 連線插槽 = await 策略執行器映射.get(策略列表[索引].類型)?.(已解析請求, 策略列表[索引].參數);
            if (連線插槽) return 連線插槽;
        } catch {}
    }
    return null;
};
const 手動資料管線 = async (可讀流, 可寫通道) => {
    const _緩衝區大小 = 緩衝區大小, _最大區塊長度 = 最大區塊長度, _啟動閾值 = 啟動閾值, _刷新時間 = 刷新時間, _安全緩衝區大小 = _緩衝區大小 - _最大區塊長度;
    let 主緩衝區 = new ArrayBuffer(_緩衝區大小), 偏移量 = 0, 計時器識別 = null, 恢復函式 = null, 正在讀取 = false, 需要刷新 = false, 累積位元組 = 0;
    const 刷新輸出 = () => {
        if (正在讀取) return 需要刷新 = true;
        偏移量 > 0 && (可寫通道.send(主緩衝區.slice(0, 偏移量)), 偏移量 = 0);
        需要刷新 = false, 計時器識別 && (clearTimeout(計時器識別), 計時器識別 = null), 恢復函式?.(), 恢復函式 = null;
    };
    const 讀取器 = 可讀流.getReader({mode: 'byob'});
    try {
        while (true) {
            正在讀取 = true;
            const {done: 是否完成, value: 讀取值} = await 讀取器.read(new Uint8Array(主緩衝區, 偏移量, _最大區塊長度));
            if (正在讀取 = false, 是否完成) break;
            主緩衝區 = 讀取值.buffer;
            const 區塊長度 = 讀取值.byteLength;
            if (區塊長度 < _最大區塊長度) {
                區塊長度 < 4096 && (累積位元組 = 0);
                偏移量 > 0 ? (偏移量 += 區塊長度, 刷新輸出()) : 可寫通道.send(讀取值.slice());
            } else {
                偏移量 += 區塊長度, 累積位元組 += 區塊長度, 需要刷新 && 刷新輸出();
                if (累積位元組 < _啟動閾值) {
                    偏移量 > _安全緩衝區大小 && 刷新輸出();
                } else {
                    計時器識別 ||= setTimeout(刷新輸出, _刷新時間);
                    偏移量 > _安全緩衝區大小 && (await new Promise(結果值 => 恢復函式 = 結果值));
                }
            }
        }
    } finally {正在讀取 = false, 刷新輸出(), 讀取器.releaseLock()}
};
const 處理網頁套接字連線 = async (網頁套接字連線, 請求) => {
    const 協議標頭 = 請求.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const 早期資料 = 協議標頭 ? Uint8Array.fromBase64(協議標頭, {alphabet: 'base64url'}) : null;
    let 傳輸控制寫入器, 處理鏈 = Promise.resolve(), 已解析請求, 傳輸控制插槽;
    const 關閉連線 = () => {if (!早期資料) {傳輸控制插槽?.close(), 網頁套接字連線?.close()}};
    const 處理訊息 = async (資料區塊) => {
        try {
            if (傳輸控制寫入器) return 傳輸控制寫入器(資料區塊);
            資料區塊 = 早期資料 ? 資料區塊 : new Uint8Array(資料區塊);
            if (資料區塊.length > 58 && 資料區塊[56] === 13 && 資料區塊[57] === 10) {
                已解析請求 = 解析透明代理封包(資料區塊);
            } else if ((已解析請求 = 解析請求封包(資料區塊))) {
                網頁套接字連線.send(new Uint8Array([資料區塊[0], 0]));
            } else {已解析請求 = 解析影子代理封包(資料區塊)}
            if (!已解析請求) return 關閉連線();
            const 負載資料 = 資料區塊.subarray(已解析請求.資料偏移);
            傳輸控制插槽 = await 建立傳輸控制連線(已解析請求, 請求);
            if (!傳輸控制插槽) return 關閉連線();
            const 寫入函式 = 傳輸控制插槽.writable.getWriter();
            if (負載資料.byteLength) 寫入函式.write(負載資料);
            傳輸控制寫入器 = (區塊值) => 寫入函式.write(區塊值);
            手動資料管線(傳輸控制插槽.readable, 網頁套接字連線);
        } catch {關閉連線()}
    };
    if (早期資料) 處理鏈 = 處理鏈.then(() => 處理訊息(早期資料));
    網頁套接字連線.addEventListener("message", 事件 => 處理鏈 = 處理鏈.then(() => 處理訊息(事件.data)));
};
export default {
    async fetch(請求) {
        if (請求.headers.get('Upgrade') === 'websocket') {
            const {0: 客戶端插槽, 1: 網頁套接字連線} = new WebSocketPair();
            // @ts-ignore
            網頁套接字連線.accept({allowHalfOpen: true}), 網頁套接字連線.binaryType = "arraybuffer";
            處理網頁套接字連線(網頁套接字連線, 請求);
            return new Response(null, {status: 101, webSocket: 客戶端插槽});
        }
        return new Response(錯誤網頁內容, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};