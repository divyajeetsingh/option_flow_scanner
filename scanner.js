// ============================================================
//  REAL-TIME OPTIONS FLOW SCANNER (NODE.JS VERSION)
//  FAST + LOW API USAGE + CONCURRENT + WEB DASHBOARD
// ============================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const readline = require('readline');
const https = require('https');
const axios = require('axios');
const { authenticator } = require('otplib');
const express = require('express');
const WebSocket = require('ws');
const { fyersModel, fyersDataSocket } = require('fyers-api-v3');

// ============================================================
// CONFIG & GLOBALS
// ============================================================

let credentials = {};
try {
    credentials = JSON.parse(fs.readFileSync(path.join(__dirname, 'credentials.json'), 'utf-8'));
} catch (e) {
    console.error("❌ Failed to read credentials.json. Please ensure it exists and is formatted correctly.", e.message);
    process.exit(1);
}

const FY_ID = credentials.FY_ID;
const APP_ID = credentials.APP_ID;
const APP_TYPE = credentials.APP_TYPE;
const SECRET_KEY = credentials.SECRET_KEY;
const TOTP_KEY = credentials.TOTP_KEY;
const PIN = credentials.PIN;
const REDIRECT_URI = credentials.REDIRECT_URI;

const PORT = 8081;
const WS_PORT = 8766;

// Settings
let STRIKES_EACH_SIDE = 1;
let VOLUME_MULTIPLIER = 30.0;
let MIN_VOLUME = 5000;
let MIN_PREMIUM = 10.0;
let COOLDOWN_MINUTES = 5;
let REFRESH_INTERVAL = 1800;

let WS_CHUNK_SIZE = 200;
let WS_CHUNK_DELAY = 0.5; // seconds
let WS_RECONNECT_DELAY = 10; // seconds

let optionSymbols = [];
const cooldownMap = {};
const latestVolume = {};
const minuteVolume = {}; // symbol -> array of length up to 4
const lastMinute = {};
const lastCumulativeVolume = {};
const symbolInfo = {};
const lastSeenLtp = {};

let cachedFoSymbols = null;
let cachedFoStocks = null;
const stockExpiryCounts = {};
const foSymbolsSet = new Set();

let wss = null;
const alertsHistory = [];
let fyers = null;
let fyersWs = null;
let wsConnected = false;

let USER_EXPIRY = null;
let FALLBACK_TO_NEAREST = false;

// ============================================================
// LICENSE CHECK
// ============================================================

async function checkLicense() {
    try {
        const checkUrl = "https://gitsof.com/copyright.json";
        const response = await axios.get(checkUrl, {
            timeout: 10000,
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });
        if (response.status !== 200) {
            console.error(`❌ License verification failed: Server returned status ${response.status}`);
            process.exit(1);
        }
        const data = response.data;
        const environments = data.environments || {};
        const allowedNames = new Set();
        for (const key in environments) {
            const env = environments[key];
            if (env && typeof env === 'object' && env.name) {
                allowedNames.add(env.name);
            }
        }
        
        const targetName = "divyajeetsinghfxinvestor";
        if (!allowedNames.has(targetName)) {
            console.error(`❌ License verification failed: '${targetName}' is not authorized.`);
            process.exit(1);
        }
        
        console.log("✅ License verified successfully.");
    } catch (e) {
        console.error(`❌ License verification error: ${e.message}`);
        process.exit(1);
    }
}

// ============================================================
// CREDENTIALS & SESSION MANAGER
// ============================================================

let sessionCookies = [];

async function fyersPost(postUrl, payload, extraHeaders = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...extraHeaders
    };
    if (sessionCookies.length > 0) {
        headers['Cookie'] = sessionCookies.join('; ');
    }

    const response = await axios.post(postUrl, payload, { 
        headers, 
        timeout: 15000, 
        validateStatus: (status) => status >= 200 && status < 400 
    });

    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
        for (const cookie of setCookie) {
            const cookiePart = cookie.split(';')[0];
            const cookieName = cookiePart.split('=')[0];
            const idx = sessionCookies.findIndex(c => c.startsWith(cookieName + '='));
            if (idx !== -1) {
                sessionCookies[idx] = cookiePart;
            } else {
                sessionCookies.push(cookiePart);
            }
        }
    }

    return response.data;
}

// ============================================================
// AUTOMATED FYERS LOGIN
// ============================================================

let ACCESS_TOKEN = null;

function loadCachedToken() {
    try {
        const cachePath = path.join(__dirname, 'access_token.json');
        if (fs.existsSync(cachePath)) {
            const data = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
            if (data && data.ACCESS_TOKEN) {
                ACCESS_TOKEN = data.ACCESS_TOKEN;
                console.log("🔑 Successfully loaded cached token from access_token.json");
                return true;
            }
        }
    } catch (e) {
        console.warn("⚠️ Could not load cached token from access_token.json:", e.message);
    }
    return false;
}

function saveTokenToCache(token) {
    try {
        const cachePath = path.join(__dirname, 'access_token.json');
        fs.writeFileSync(cachePath, JSON.stringify({ ACCESS_TOKEN: token }, null, 4));
        console.log("💾 Saved token to access_token.json");
    } catch (e) {
        console.warn("⚠️ Failed to write to access_token.json:", e.message);
    }
}

async function performLogin() {
    console.log("🚀 Starting automated Fyers programmatic authentication flow...");
    sessionCookies = [];

    // Step 1: Send Login OTP
    console.log("Step 1: Sending Login OTP request...");
    const r1 = await fyersPost("https://api-t2.fyers.in/vagator/v2/send_login_otp", {
        fy_id: FY_ID,
        app_id: "2"
    });

    if (r1.s !== "ok") {
        throw new Error(`Fyers send_login_otp failed: ${JSON.stringify(r1)}`);
    }
    let requestKey = r1.request_key;
    console.log("✅ Login OTP request successful.");

    // Step 2: Generate and Verify TOTP
    console.log("Step 2: Generating and verifying TOTP token...");
    authenticator.options = { digits: 6, step: 30 };
    const totp = authenticator.generate(TOTP_KEY);

    const r2 = await fyersPost("https://api-t2.fyers.in/vagator/v2/verify_otp", {
        request_key: requestKey,
        otp: totp
    });

    if (r2.s !== "ok") {
        throw new Error(`Fyers verify_otp failed: ${JSON.stringify(r2)}`);
    }
    requestKey = r2.request_key;
    console.log("✅ TOTP verification successful.");

    // Step 3: Verify security PIN
    console.log("Step 3: Verifying user security PIN...");
    const r3 = await fyersPost("https://api-t2.fyers.in/vagator/v2/verify_pin", {
        request_key: requestKey,
        identity_type: "pin",
        identifier: PIN
    });

    if (r3.s !== "ok") {
        throw new Error(`Fyers verify_pin failed: ${JSON.stringify(r3)}`);
    }
    const access_token_stage1 = r3.data.access_token;
    console.log("✅ PIN verification successful.");

    // Step 4: Generate authorization code (auth_code)
    console.log("Step 4: Requesting redirect URL to extract auth code...");
    const appIdWithoutType = APP_ID.replace("-100", "");
    const r4 = await fyersPost("https://api-t1.fyers.in/api/v3/token", {
        fyers_id: FY_ID,
        app_id: appIdWithoutType,
        redirect_uri: REDIRECT_URI,
        appType: APP_TYPE,
        code_challenge: "",
        state: "sample_state",
        scope: "",
        nonce: "",
        response_type: "code",
        create_cookie: true
    }, {
        Authorization: `Bearer ${access_token_stage1}`
    });

    if (r4.s !== "ok") {
        throw new Error(`Fyers auth code generation failed: ${JSON.stringify(r4)}`);
    }

    const redirectUrl = r4.Url;
    const parsedUrl = url.parse(redirectUrl, true);
    const authCode = parsedUrl.query.auth_code;
    if (!authCode) {
        throw new Error(`Could not extract auth_code from redirect URL: ${redirectUrl}`);
    }
    console.log(`✅ Auth Code successfully generated: ${authCode.slice(0, 15)}...`);

    // Step 5: Exchange authorization code for access token
    console.log("Step 5: Exchanging auth code for final Fyers API access token...");
    const fyersObj = new fyersModel();
    fyersObj.setAppId(APP_ID);
    fyersObj.setRedirectUrl(REDIRECT_URI);

    const tokenResponse = await fyersObj.generate_access_token({
        client_id: APP_ID,
        secret_key: SECRET_KEY,
        auth_code: authCode
    });

    if (!tokenResponse || tokenResponse.s !== "ok" || !tokenResponse.access_token) {
        throw new Error(`Token generation failed: ${JSON.stringify(tokenResponse)}`);
    }

    const accessToken = tokenResponse.access_token;
    console.log("🎉 Programmatic login complete! Access token generated successfully.");
    
    saveTokenToCache(accessToken);
    return accessToken;
}

// ============================================================
// SETTINGS LOADER
// ============================================================

function loadSettings() {
    const settingsFile = path.join(__dirname, 'options_flow_settings.json');
    const defaults = {
        expiry_mode: "automatic",
        manual_expiry_code: "",
        fallback_to_nearest: false,
        strikes_each_side: 1,
        volume_multiplier: 30.0,
        min_volume: 5000,
        min_premium: 10.0,
        cooldown_minutes: 5,
        refresh_interval: 1800
    };

    let data = defaults;
    try {
        if (fs.existsSync(settingsFile)) {
            data = JSON.parse(fs.readFileSync(settingsFile, 'utf-8'));
        } else {
            fs.writeFileSync(settingsFile, JSON.stringify(defaults, null, 4));
        }
    } catch (e) {
        console.warn(`⚠️ Error reading settings file: ${e.message}. Using default values.`);
    }

    STRIKES_EACH_SIDE = parseInt(data.strikes_each_side || 1);
    VOLUME_MULTIPLIER = parseFloat(data.volume_multiplier || 30.0);
    MIN_VOLUME = parseInt(data.min_volume || 5000);
    MIN_PREMIUM = parseFloat(data.min_premium || 10.0);
    COOLDOWN_MINUTES = parseInt(data.cooldown_minutes || 5);
    REFRESH_INTERVAL = parseInt(data.refresh_interval || 1800);
    FALLBACK_TO_NEAREST = !!data.fallback_to_nearest;

    const expiryMode = data.expiry_mode || "automatic";
    if (expiryMode === "manual") {
        const manualCode = (data.manual_expiry_code || "").trim().toUpperCase();

        const allExpiries = new Set();
        for (const stockName in stockExpiryCounts) {
            for (const exp in stockExpiryCounts[stockName]) {
                allExpiries.add(exp);
            }
        }

        const resolved = parseUserDateToExpiryCode(manualCode, allExpiries);
        if (resolved) {
            USER_EXPIRY = resolved;
        } else if (allExpiries.has(manualCode)) {
            USER_EXPIRY = manualCode;
        } else {
            USER_EXPIRY = null;
            console.warn(`⚠️ Could not resolve manual expiry: ${manualCode}. Defaulting to automatic nearest.`);
        }
    } else {
        USER_EXPIRY = null;
    }

    console.log("\n" + "=".repeat(50));
    console.log("         LOADED SETTINGS FROM CONFIG FILE");
    console.log("=".repeat(50));
    console.log(`  Strikes Each Side: ${STRIKES_EACH_SIDE}`);
    console.log(`  Volume Multiplier: ${VOLUME_MULTIPLIER}x`);
    console.log(`  Min Volume: ${MIN_VOLUME}`);
    console.log(`  Min Premium: ${MIN_PREMIUM}`);
    console.log(`  Cooldown Minutes: ${COOLDOWN_MINUTES}m`);
    console.log(`  Refresh Interval: ${REFRESH_INTERVAL}s`);
    console.log(`  Expiry Mode: ${expiryMode.toUpperCase()} (${USER_EXPIRY ? USER_EXPIRY : 'NEAREST'})`);
    console.log(`  Expiry Fallback: ${FALLBACK_TO_NEAREST ? 'Enabled' : 'Disabled'}`);
    console.log("=".repeat(50) + "\n");
}

// ============================================================
// STRIKE STEP CALCULATOR & DATE UTILS
// ============================================================

function autoStrikeStep(price) {
    if (price >= 40000) return 1000;
    if (price >= 20000) return 500;
    if (price >= 10000) return 200;
    if (price >= 5000)  return 100;
    if (price >= 2000)  return 50;
    if (price >= 1000)  return 20;
    if (price >= 500)   return 10;
    if (price >= 100)   return 5;
    return 1;
}

function getStrikeStep(name, price) {
    if (name === "NIFTY") return 50;
    if (name === "BANKNIFTY") return 100;
    if (name === "FINNIFTY") return 50;
    if (name === "MIDCPNIFTY") return 25;
    return autoStrikeStep(price);
}

function roundToStep(price, step) {
    return Math.round(price / step) * step;
}

function parseUserDateToExpiryCode(userDateStr, allExpiries) {
    const parts = userDateStr.match(/[a-zA-Z]+|\d+/g);
    if (!parts) return null;

    let day = null;
    let month = null;
    let year = 2026;

    const monthsMap = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
        'january': 1, 'february': 2, 'march': 3, 'april': 4, 'june': 6,
        'july': 7, 'august': 8, 'september': 9, 'october': 10, 'november': 11, 'december': 12
    };

    for (const part of parts) {
        const partLower = part.toLowerCase();
        if (partLower in monthsMap) {
            month = monthsMap[partLower];
        } else if (/^\d+$/.test(part)) {
            const val = parseInt(part);
            if (val > 1000) {
                year = val;
            } else if (val > 31) {
                year = 2000 + val;
            } else if (day === null) {
                day = val;
            } else if (month === null) {
                month = val;
            }
        }
    }

    if (day === null || month === null) return null;

    const yy = String(year).slice(-2);
    const mmmList = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
    const mmm = mmmList[month - 1];
    const monthlyCode = `${yy}${mmm}`;

    let mChar = String(month);
    if (month === 10) mChar = 'O';
    else if (month === 11) mChar = 'N';
    else if (month === 12) mChar = 'D';
    const dd = String(day).padStart(2, '0');
    const weeklyCode = `${yy}${mChar}${dd}`;

    if (allExpiries.has(weeklyCode)) return weeklyCode;
    if (allExpiries.has(monthlyCode)) return monthlyCode;

    return null;
}

function getNearestExpiry(foName) {
    const counts = stockExpiryCounts[foName];
    if (!counts) return null;
    return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b);
}

function getUnderlyingSymbol(name) {
    if (name === "NIFTY") return "NSE:NIFTY50-INDEX";
    if (name === "BANKNIFTY") return "NSE:NIFTYBANK-INDEX";
    if (name === "FINNIFTY") return "NSE:FINNIFTY-INDEX";
    if (name === "MIDCPNIFTY") return "NSE:MIDCPNIFTY-INDEX";
    return `NSE:${name}-EQ`;
}

// ============================================================
// DATA LOADERS (NSE_FO CSV)
// ============================================================

async function downloadFile(downloadUrl, dest) {
    const writer = fs.createWriteStream(dest);
    const response = await axios({
        url: downloadUrl,
        method: 'GET',
        responseType: 'stream',
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
    });
}

function parseFoSymbolsData(foSymbols) {
    foSymbolsSet.clear();
    for (const key in stockExpiryCounts) delete stockExpiryCounts[key];

    for (const sym of foSymbols) {
        if (!sym.startsWith("NSE:")) continue;
        foSymbolsSet.add(sym);

        const core = sym.replace("NSE:", "").slice(0, -2); // SBIN26JUN620 or NIFTY2660918100
        let idx = 0;
        while (idx < core.length && !/^\d$/.test(core[idx])) {
            idx++;
        }
        const stockName = core.slice(0, idx);
        const expiryStrike = core.slice(idx);
        if (expiryStrike.length >= 5) {
            const expiry = expiryStrike.slice(0, 5);
            if (!stockExpiryCounts[stockName]) {
                stockExpiryCounts[stockName] = {};
            }
            stockExpiryCounts[stockName][expiry] = (stockExpiryCounts[stockName][expiry] || 0) + 1;
        }
    }
}

async function loadFoSymbols() {
    const csvFilename = path.join(__dirname, 'NSE_FO.csv');
    let useCached = false;

    if (fs.existsSync(csvFilename)) {
        try {
            const stats = fs.statSync(csvFilename);
            const mtime = new Date(stats.mtime);
            const today = new Date();
            if (mtime.getDate() === today.getDate() &&
                mtime.getMonth() === today.getMonth() &&
                mtime.getFullYear() === today.getFullYear()) {
                useCached = true;
            }
        } catch (e) {
            console.error("Error checking cache timestamp:", e);
        }
    }

    if (useCached) {
        console.log("Loading NSE_FO.csv from local cache...");
    } else {
        console.log("Downloading NSE_FO.csv...");
        const downloadUrl = "https://public.fyers.in/sym_details/NSE_FO.csv";
        try {
            await downloadFile(downloadUrl, csvFilename);
            console.log("Successfully downloaded and cached NSE_FO.csv.");
        } catch (e) {
            console.error(`⚠️ Error downloading NSE_FO.csv: ${e.message}`);
            if (fs.existsSync(csvFilename)) {
                console.log("Falling back to existing cached NSE_FO.csv...");
            } else {
                throw e;
            }
        }
    }

    const fileStream = fs.createReadStream(csvFilename);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    const foSymbols = [];
    const foStocks = new Set();

    for await (const line of rl) {
        if (!line.trim()) continue;
        const parts = line.split(',');
        if (parts.length < 10) continue;
        
        const sym = parts[9].replace(/"/g, '').trim();
        const disp = parts[1].replace(/"/g, '').trim();

        if (sym.startsWith("NSE:") && (sym.endsWith("CE") || sym.endsWith("PE"))) {
            symbolInfo[sym] = disp;
            foSymbols.push(sym);

            // Extract stock name
            const core = sym.replace("NSE:", "").slice(0, -2);
            let name = "";
            for (let i = 0; i < core.length; i++) {
                if (/^\d$/.test(core[i])) {
                    break;
                }
                name += core[i];
            }
            if (name) {
                foStocks.add(name);
            }
        }
    }

    return {
        foSymbols,
        foStocks: Array.from(foStocks).sort()
    };
}

// ============================================================
// UNIVERSE BUILDER
// ============================================================

async function fetchCmps(symbolsList) {
    const cmpMap = {};
    const chunkSize = 50;
    for (let i = 0; i < symbolsList.length; i += chunkSize) {
        const chunk = symbolsList.slice(i, i + chunkSize);
        const symbolsStr = chunk.join(",");
        try {
            const q = await fyers.getQuotes(chunk);
            if (q && q.s === "ok" && Array.isArray(q.d)) {
                for (const item of q.d) {
                    const symbol = item.n;
                    const lp = item.v ? item.v.lp : null;
                    if (symbol && lp !== null && lp !== undefined) {
                        cmpMap[symbol] = parseFloat(lp);
                    }
                }
            }
        } catch (e) {
            console.error(`⚠️ Error fetching quotes chunk starting with ${chunk[0]}: ${e.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    return cmpMap;
}

function buildOptionSymbols(name, cmp, expiry, step) {
    const atm = roundToStep(cmp, step);
    const symbols = [];
    for (let i = -STRIKES_EACH_SIDE; i <= STRIKES_EACH_SIDE; i++) {
        const strike = atm + i * step;
        symbols.push(`NSE:${name}${expiry}${strike}CE`);
        symbols.push(`NSE:${name}${expiry}${strike}PE`);
    }
    return symbols;
}

async function buildUniverse(foSymbols = null, foStocks = null) {
    try {
        if (!foSymbols || !foStocks) {
            if (cachedFoSymbols && cachedFoStocks) {
                foSymbols = cachedFoSymbols;
                foStocks = cachedFoStocks;
            } else {
                const loaded = await loadFoSymbols();
                foSymbols = loaded.foSymbols;
                foStocks = loaded.foStocks;
                parseFoSymbolsData(foSymbols);
                cachedFoSymbols = foSymbols;
                cachedFoStocks = foStocks;
            }
        }

        const finalSymbols = [];
        const underlyingSymbols = foStocks.map(name => getUnderlyingSymbol(name));

        console.log(`Fetching current prices (LTP) for ${underlyingSymbols.length} underlying symbols...`);
        const cmpMap = await fetchCmps(underlyingSymbols);

        for (const name of foStocks) {
            try {
                const underlying = getUnderlyingSymbol(name);
                const cmp = cmpMap[underlying] || 0;
                if (cmp === 0) continue;

                let expiry = null;
                if (USER_EXPIRY) {
                    if (stockExpiryCounts[name] && USER_EXPIRY in stockExpiryCounts[name]) {
                        expiry = USER_EXPIRY;
                    } else if (FALLBACK_TO_NEAREST) {
                        expiry = getNearestExpiry(name);
                    } else {
                        continue;
                    }
                } else {
                    expiry = getNearestExpiry(name);
                }

                if (!expiry) continue;

                const step = getStrikeStep(name, cmp);
                const syms = buildOptionSymbols(name, cmp, expiry, step);

                const validSyms = syms.filter(s => foSymbolsSet.has(s));
                if (validSyms.length > 0) {
                    finalSymbols.push(...validSyms);
                    const sampleDisplay = symbolInfo[validSyms[0]] || expiry;
                    console.log(`  ${name}: ${validSyms.length} symbols — E.g. ${sampleDisplay}`);
                }
            } catch (err) {
                console.error(`  ${name}: ERROR — ${err.message}`);
            }
        }

        optionSymbols = Array.from(new Set(finalSymbols));
        console.log(`\nTOTAL OPTIONS = ${optionSymbols.length}`);
    } catch (e) {
        console.error("Error building universe:", e);
    }
}

// ============================================================
// DYNAMIC RE-SUBSCRIBE ON SETTINGS CHANGE
// ============================================================

async function rebuildUniverseAndResubscribe() {
    console.log("\n🔄 Rebuilding options universe based on new settings...");
    try {
        const oldSymbols = [...optionSymbols];
        await buildUniverse(cachedFoSymbols, cachedFoStocks);

        if (fyersWs) {
            console.log("🔄 Dynamic option universe resubscription starting...");
            const oldSet = new Set(oldSymbols);
            const newSet = new Set(optionSymbols);

            const toUnsubscribe = oldSymbols.filter(s => !newSet.has(s));
            const toSubscribe = optionSymbols.filter(s => !oldSet.has(s));

            // Unsubscribe in chunks
            if (toUnsubscribe.length > 0) {
                console.log(`  📤 Unsubscribing from ${toUnsubscribe.length} old option symbols...`);
                for (let i = 0; i < toUnsubscribe.length; i += WS_CHUNK_SIZE) {
                    const chunk = toUnsubscribe.slice(i, i + WS_CHUNK_SIZE);
                    try {
                        fyersWs.unsubscribe(chunk, "symbolUpdate");
                        console.log(`    Unsubscribed chunk ${Math.floor(i/WS_CHUNK_SIZE) + 1}/${Math.ceil(toUnsubscribe.length/WS_CHUNK_SIZE)} (${chunk.length} symbols)`);
                    } catch (err) {
                        console.error(`    Unsubscribe chunk error: ${err.message}`);
                    }
                    await new Promise(resolve => setTimeout(resolve, WS_CHUNK_DELAY * 1000));
                }
            }

            // Subscribe in chunks
            if (toSubscribe.length > 0) {
                console.log(`  📥 Subscribing to ${toSubscribe.length} new option symbols...`);
                for (let i = 0; i < toSubscribe.length; i += WS_CHUNK_SIZE) {
                    const chunk = toSubscribe.slice(i, i + WS_CHUNK_SIZE);
                    try {
                        fyersWs.subscribe(chunk, "symbolUpdate");
                        console.log(`    Subscribed chunk ${Math.floor(i/WS_CHUNK_SIZE) + 1}/${Math.ceil(toSubscribe.length/WS_CHUNK_SIZE)} (${chunk.length} symbols)`);
                    } catch (err) {
                        console.error(`    Subscription chunk error: ${err.message}`);
                    }
                    await new Promise(resolve => setTimeout(resolve, WS_CHUNK_DELAY * 1000));
                }
            }
            console.log(`✅ Dynamic option universe update complete. ${optionSymbols.length} symbols currently active.`);
        }
    } catch (e) {
        console.error("❌ Error rebuilding universe on settings change:", e);
    }
}

// ============================================================
// SPIKE DETECTION ENGINE
// ============================================================

function buildAlertText(symbol, ratio, currentVol, avgVol, ltp, incrementalVol, prevCumulative, currentCumulative) {
    const direction = symbol.endsWith("CE") ? "🟢 CE FLOW" : "🔴 PE FLOW";
    const displayName = symbolInfo[symbol] || symbol;
    
    const timeStr = new Date().toLocaleTimeString('en-IN', { hour12: false });
    
    return `
${direction}

📌 ${displayName}
🔍 Symbol: ${symbol}

💰 LTP: ₹${ltp.toFixed(2)}

📈 Tick Change (Vol): +${incrementalVol.toLocaleString('en-IN')}
🔄 Prev Cumulative Vol: ${prevCumulative.toLocaleString('en-IN')}
💎 Current Cumulative Vol: ${currentCumulative.toLocaleString('en-IN')}

🔥 Current Minute Vol: ${currentVol.toLocaleString('en-IN')}
📊 Avg Minute Vol: ${Math.round(avgVol).toLocaleString('en-IN')}
⚡ Spike Ratio: ${ratio.toFixed(2)}x

🕐 ${timeStr}
`;
}

function detectSpike(symbol, ltp, currentVolume, incrementalVolume, prevCumulative, currentCumulative) {
    if (currentVolume < MIN_VOLUME) return;
    if (ltp < MIN_PREMIUM) return;

    const history = minuteVolume[symbol] || [];
    if (history.length < 3) return;

    const avgVolume = history.reduce((sum, v) => sum + v, 0) / history.length;
    if (avgVolume <= 0) return;

    const ratio = currentVolume / avgVolume;
    if (ratio < VOLUME_MULTIPLIER) return;

    const now = new Date();
    if (cooldownMap[symbol]) {
        const elapsedMinutes = (now - cooldownMap[symbol]) / 60000;
        if (elapsedMinutes < COOLDOWN_MINUTES) return;
    }

    cooldownMap[symbol] = now;

    const alertText = buildAlertText(symbol, ratio, currentVolume, avgVolume, ltp, incrementalVolume, prevCumulative, currentCumulative);
    console.log(alertText);

    const timeStr = now.toLocaleTimeString('en-IN', { hour12: false });
    const alertData = {
        symbol: symbol,
        display_name: symbolInfo[symbol] || symbol,
        timestamp: timeStr,
        ltp: ltp,
        direction: symbol.endsWith("CE") ? "CE" : "PE",
        ratio: ratio,
        minute_volume: currentVolume,
        avg_volume: avgVolume,
        incremental_volume: incrementalVolume,
        prev_cumulative_volume: prevCumulative,
        current_cumulative_volume: currentCumulative
    };

    alertsHistory.push(alertData);
    broadcastData({ type: "alert", data: alertData });
}

function processTick(message) {
    if (!message || typeof message !== 'object') return;

    const symbol = message.symbol;
    if (!symbol) return;

    const ltpVal = message.ltp;
    if (ltpVal !== undefined && ltpVal !== null) {
        lastSeenLtp[symbol] = parseFloat(ltpVal);
    }

    const ltp = lastSeenLtp[symbol] || 0.0;
    const cumulativeVolume = parseInt(message.vol_traded_today || 0);
    const now = new Date();
    
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const currentMinute = `${hh}:${mm}`;

    if (lastCumulativeVolume[symbol] === undefined) {
        lastCumulativeVolume[symbol] = cumulativeVolume;
        lastMinute[symbol] = currentMinute;
        latestVolume[symbol] = 0;
        return;
    }

    const previousCumulative = lastCumulativeVolume[symbol];
    const incrementalVolume = Math.max(cumulativeVolume - previousCumulative, 0);
    lastCumulativeVolume[symbol] = cumulativeVolume;

    if (lastMinute[symbol] === undefined) {
        lastMinute[symbol] = currentMinute;
    }

    // New minute — rotate bucket
    if (currentMinute !== lastMinute[symbol]) {
        if (!minuteVolume[symbol]) {
            minuteVolume[symbol] = [];
        }
        minuteVolume[symbol].push(latestVolume[symbol] || 0);
        if (minuteVolume[symbol].length > 4) {
            minuteVolume[symbol].shift();
        }
        latestVolume[symbol] = 0;
        lastMinute[symbol] = currentMinute;
    }

    latestVolume[symbol] = (latestVolume[symbol] || 0) + incrementalVolume;
    const currentVolume = latestVolume[symbol];

    detectSpike(symbol, ltp, currentVolume, incrementalVolume, previousCumulative, cumulativeVolume);
}

function onMessage(msg) {
    try {
        if (!msg) return;
        let data = msg;
        if (typeof msg === 'string') {
            data = JSON.parse(msg);
        }
        
        if (data.symbol) {
            processTick(data);
        } else if (data.d) {
            if (Array.isArray(data.d)) {
                for (const item of data.d) {
                    processTick(item);
                }
            } else if (typeof data.d === 'object') {
                processTick(data.d);
            }
        }
    } catch (e) {
        console.error("onMessage error:", e);
    }
}

// ============================================================
// EXCHANGES & CONNECTIONS
// ============================================================

function startFyersWebsocket() {
    console.log("Connecting to Fyers Data WebSocket...");
    wsConnected = false;

    const accessTokenStr = `${APP_ID}:${ACCESS_TOKEN}`;
    fyersWs = new fyersDataSocket(accessTokenStr, "", false);

    fyersWs.on("connect", async () => {
        wsConnected = true;
        console.log("WebSocket connected — subscribing in chunks...");

        const total = optionSymbols.length;
        console.log(`Subscribing to ${total} symbols in chunks of ${WS_CHUNK_SIZE}...`);
        
        for (let i = 0; i < total; i += WS_CHUNK_SIZE) {
            const chunk = optionSymbols.slice(i, i + WS_CHUNK_SIZE);
            try {
                fyersWs.subscribe(chunk, "symbolUpdate");
                console.log(`  Subscribed chunk ${Math.floor(i / WS_CHUNK_SIZE) + 1}/${Math.ceil(total / WS_CHUNK_SIZE)} (${chunk.length} symbols)`);
            } catch (e) {
                console.error(`  Chunk subscription error: ${e.message}`);
            }
            await new Promise(resolve => setTimeout(resolve, WS_CHUNK_DELAY * 1000));
        }
        console.log(`Subscription complete — ${total} symbols active.`);
    });

    fyersWs.on("message", (msg) => {
        onMessage(msg);
    });

    fyersWs.on("error", (err) => {
        console.error("Fyers WebSocket error:", err);
        wsConnected = false;
    });

    fyersWs.on("close", (code) => {
        console.log(`Fyers WebSocket closed: ${code}. Reconnecting in ${WS_RECONNECT_DELAY} seconds...`);
        wsConnected = false;
        setTimeout(() => {
            console.log("Attempting to reconnect Fyers WebSocket...");
            fyersWs.connect();
        }, WS_RECONNECT_DELAY * 1000);
    });

    fyersWs.connect();
}

// ============================================================
// LOCAL WEBSOCKET BROADCASTER SERVER
// ============================================================

function runWsServer() {
    wss = new WebSocket.Server({ port: WS_PORT });
    console.log(`🔌 WebSocket server started on ws://localhost:${WS_PORT}`);

    wss.on('connection', (ws) => {
        console.log("Dashboard client connected.");
        ws.send(JSON.stringify({
            type: "init",
            data: alertsHistory
        }));

        ws.on('error', (err) => {
            console.error("Dashboard client WS error:", err);
        });

        ws.on('close', () => {
            console.log("Dashboard client disconnected.");
        });
    });
}

function broadcastData(messageObj) {
    if (!wss) return;
    const msgStr = JSON.stringify(messageObj);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(msgStr);
        }
    });
}

// ============================================================
// EXPRESS LOCAL WEB SERVER
// ============================================================

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get(['/', '/index.html', '/options_flow', '/options_flow.html'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'options_flow.html'));
});

app.get('/api/settings', (req, res) => {
    try {
        const settingsFile = path.join(__dirname, 'options_flow_settings.json');
        if (fs.existsSync(settingsFile)) {
            const settingsData = fs.readFileSync(settingsFile, 'utf-8');
            res.json(JSON.parse(settingsData));
        } else {
            res.status(404).json({ error: "Settings file not found" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/settings', async (req, res) => {
    try {
        const settingsFile = path.join(__dirname, 'options_flow_settings.json');
        const newSettings = req.body;
        fs.writeFileSync(settingsFile, JSON.stringify(newSettings, null, 4));
        
        loadSettings();
        rebuildUniverseAndResubscribe();

        res.json({ status: "success", message: "Settings saved successfully." });
    } catch (e) {
        res.status(500).json({ status: "error", message: e.message });
    }
});

function runHttpServer() {
    app.listen(PORT, () => {
        console.log(`🌍 Web server started at http://localhost:${PORT}`);
    });
}

// ============================================================
// MAIN PIPELINE
// ============================================================

async function verifyToken() {
    try {
        const testQuote = await fyers.getQuotes(["NSE:NIFTY50-INDEX"]);
        if (!testQuote || testQuote.s !== "ok") {
            throw new Error(`Token verification quote request failed: ${JSON.stringify(testQuote)}`);
        }
        console.log("✅ Token verification successful.");
        return true;
    } catch (e) {
        console.log(`❌ Loaded token is invalid or expired: ${e.message}. Performing a fresh login...`);
        return false;
    }
}

async function main() {
    await checkLicense();

    fyers = new fyersModel({
        path: "",
        enableLogging: false
    });
    fyers.setAppId(APP_ID);

    let isTokenValid = false;
    if (loadCachedToken()) {
        fyers.setAccessToken(ACCESS_TOKEN);
        isTokenValid = await verifyToken();
    }

    if (!isTokenValid) {
        const cachePath = path.join(__dirname, 'access_token.json');
        if (fs.existsSync(cachePath)) {
            try {
                fs.unlinkSync(cachePath);
                console.log("🗑️ Removed invalid/expired token file: access_token.json");
            } catch (diskErr) {
                console.error("⚠️ Failed to remove invalid token file:", diskErr.message);
            }
        }
        ACCESS_TOKEN = await performLogin();
        fyers.setAccessToken(ACCESS_TOKEN);
    }

    const loaded = await loadFoSymbols();
    cachedFoSymbols = loaded.foSymbols;
    cachedFoStocks = loaded.foStocks;
    parseFoSymbolsData(cachedFoSymbols);

    loadSettings();

    await buildUniverse(cachedFoSymbols, cachedFoStocks);

    runHttpServer();
    runWsServer();

    // Universe periodic refresh
    setInterval(async () => {
        console.log("\nRefreshing universe...");
        try {
            await buildUniverse();
            console.log("Universe refreshed.");
        } catch (e) {
            console.error("Universe refresh error:", e);
        }
    }, REFRESH_INTERVAL * 1000);

    console.log(`\n🚀 OPTIONS FLOW SCANNER STARTED`);
    console.log(`📦 Symbols: ${optionSymbols.length}`);
    console.log(`📅 Expiry Mode: ${USER_EXPIRY ? USER_EXPIRY : 'Automatic Nearest'}`);
    console.log(`🌍 Web dashboard: http://localhost:${PORT}`);
    console.log(`🔌 WebSocket server: ws://localhost:${WS_PORT}`);
    console.log("=".repeat(50) + "\n");

    startFyersWebsocket();
}

main().catch(err => {
    console.error("Fatal error in options flow scanner:", err);
    process.exit(1);
});
