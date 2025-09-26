/*
 * ZTE-Script-NG (for ZTE G5TC and later models)
 *
 * (c) 2025 by Thomas Pöchtrager (t.poechtrager@gmail.com)
 * LICENSE: AGPLv3+
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 */

(function() {
  const VERSION = '2025-09-25';

  // globals
  let currentNetInfo = null;

  // --- Logging helpers ---
  function scriptMsg(msg) {
    console.log(`[script]: ${msg}`);
  }

  function scriptErrorMsg(msg) {
    console.error(`[script error]: ${msg}`);
  }

  // --- ubus call helper ---
  async function callUbus(calls, sessionId=null, omitErrorMsg=false) {
    sessionId = sessionId || sessionStorage.getItem("ct");
    const callsArray = Array.isArray(calls) ? calls : [calls];

    const req = callsArray.map((c, i) => ({
      jsonrpc: "2.0",
      id: i,
      method: "call",
      params: [sessionId, c.service, c.method, c.params || {}]
    }));

    // double t on purpose. Script marker in network log.
    const res = await fetch("/ubus/?t=" + Date.now() + "&t=" + Date.now(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Z-Mode": "1", // This will prevent automatic logout...
      },
      body: JSON.stringify(req)
    }).then(r => r.json());

    const byId = new Map(res.map(r => [r.id, r]));

    const results = req.map(rq => {
      const r = byId.get(rq.id);
      const code = r?.result?.[0];
      if (code === 0) {
        return { success: true, id: rq.id, data: r.result[1] };
      } else {
        if (!omitErrorMsg) {
          scriptErrorMsg(
            `ubus call failed → id=${rq.id}, code=${code}, request=${JSON.stringify(rq)}`
          );
        }
        return { success: false, id: rq.id, data: null };
      }
    });

    return Array.isArray(calls) ? results : results[0];
  }

  // --- login ---
  async function getLoginPasswordHash(store = true) {
    const existing = localStorage.getItem("ScriptPasswordHash");
    if (existing) {
      return existing;
    }

    const plain = prompt(
      store
        ? "Enter your router password (SHA256 hash will be stored in localStorage):"
        : "Enter your router password:"
    );
    if (!plain) {
      return false;
    }

    const hash = await sha256Hex(plain);
    if (store) {
      localStorage.setItem("ScriptPasswordHash", hash);
    }
    return hash;
  }

  function clearLoginPasswordHash() {
    localStorage.removeItem("ScriptPasswordHash");
  }

  async function check_login() {
    try {
      const res = await callUbus({
        service: "zwrt_web",
        method: "web_developer_login_info",
        params: {}
      }, null, true);
      return res.success && res.data;
    } catch {
      return false;
    }
  }

  async function login(login_type, password_hash) {
    const sessionId =
      login_type === "web_login"
        ? "00000000000000000000000000000000"
        : sessionStorage.getItem("ct");

    const saltRes = await callUbus(
      {
        service: "zwrt_web",
        method: "web_login_info",
        params: {}
      },
      sessionId
    );

    const sault = saltRes?.data?.zte_web_sault;
    if (!sault) {
      throw new Error("Could not retrieve salt");
    }

    const first = await password_hash;
    const finalHash = await sha256Hex(first + sault);

    const loginRes = await callUbus(
      {
        service: "zwrt_web",
        method: login_type,
        params: { password: finalHash }
      },
      sessionId
    );

    const loginResult = loginRes?.data;
    if (loginResult?.result === 0) {
      if (login_type === "web_login" && loginResult?.ubus_rpc_session) {
        sessionStorage.setItem("ct", loginResult.ubus_rpc_session);
      }
      return true;
    }

    return false;
  }

  async function normal_login() {
    return login("web_login", getLoginPasswordHash());
  }

  async function developer_login() {
    return login("web_developer_option_login", getLoginPasswordHash(false));
  }

  // --- helpers ---
  function showBanner() {
    console.log(`
        ZTE-Script-NG v${VERSION} loaded.

        This script is free to use and licensed under AGPLv3.

        Creating it was a lot of work.
        If it is helpful to you and you would like to, a tip would be much appreciated.
        PayPal: t.poechtrager@gmail.com -- Thank you.
    `.replace(/^\s*\n/, "").replace(/^[ \t]+/gm, ""));
  }

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(str)
    );
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  function toHex(val, withPrefix = true) {
    if (val == null || isNaN(val)) return "-";
    const hex = Number(val).toString(16).toUpperCase();
    return withPrefix ? "0x" + hex : hex;
  }

  function formatSeconds(seconds) {
    if (!seconds || isNaN(seconds)) return "-";

    let s = parseInt(seconds, 10);
    const d = Math.floor(s / 86400); s %= 86400;
    const h = Math.floor(s / 3600); s %= 3600;
    const m = Math.floor(s / 60);   s %= 60;

    const parts = [];
    if (d > 0) parts.push(d + "d");
    if (h > 0) parts.push(h + "h");
    if (m > 0) parts.push(m + "m");
    if (s > 0 || parts.length === 0) parts.push(s + "s");

    return parts.join("");
  }

  function setCurrent4gMask(maskNum) {
    const panel = document.getElementById("router-info-panel");
    if (panel) {
      panel.dataset.current4gMask = maskNum.toString();
    }
  }

  function get4gBandMask(bandNumber) {
    return 1n << BigInt(bandNumber - 1);
  }

  function setCurrent5gBands(bands) {
    const panel = document.getElementById("router-info-panel");
    if (panel) {
      panel.dataset.current5gBands = bands.join(",");
    }
  }

  function is4gBasedNetworkType(type) {
    return type === "LTE" || type === "ENDC" || type === "LTE-NSA";
  }

  function is5gBasedNetworkType(type) {
    return type === "SA" || type === "ENDC" || type === "LTE-NSA";
  }

  // --- Network Signal Parsing ---

  function convert4gEarfcnToMhz(earfcn) {
    const lteBands = [
      // [band, f_dl_low, n_offs_dl, n_min_dl, n_max_dl]
      [1, 2110, 0,     0,    599],
      [3, 1805, 1200, 1200,  1949],
      [4, 2110, 1950, 1950,  2399],
      [5, 869,  2400, 2400,  2649],
      [7, 2620, 2750, 2750,  3449],
      [8, 925,  3450, 3450,  3799],
      [20, 791, 6150, 6150,  6449],
      [28, 758, 9210, 9210,  9659],
      [32, 1452, 9920, 9920, 10359], // DL only
      [38, 2570, 37750, 37750, 38249],
      [40, 2300, 38650, 38650, 39649],
      [42, 3400, 41590, 41590, 43589],
      [43, 3600, 43590, 43590, 45589],
    ];

    for (const [band, fdl, noffdl, nminDl, nmaxDl] of lteBands) {
      if (earfcn >= nminDl && earfcn <= nmaxDl) {
        return {
          band,
          dlMHz: fdl + 0.1 * (earfcn - noffdl)
        };
      }
    }
    return null; // unknown EARFCN
  }

  function convert5gArfcnToMhz(arfcn) {
    // Global ARFCN -> MHz mapping according to 3GPP TS 38.104
    function arfcnToMHz(N) {
      if (N >= 0 && N <= 599999) {
        return 0.005 * N;
      } else if (N >= 600000 && N <= 2016666) {
        return 3000 + 0.015 * (N - 600000);
      } else if (N >= 2016667 && N <= 3279165) {
        return 24250 + 0.06 * (N - 2016667);
      }
      return null;
    }

    // Subset of most relevant NR bands with ARFCN ranges
    // [band, n_min, n_max]
    const nrBands = [
      [1,   422000, 434000],
      [3,   361000, 376000],
      [5,   173800, 178800],
      [7,   524000, 538000],
      [8,   185000, 192000],
      [28,  151600, 160600],
      [40,  460000, 480000],
      [41,  499200, 537999],
      [75,  286400, 303400], // DL only
      [78,  620000, 653333],
      [79,  693334, 733333],
      // mmWave (FR2)
      [257, 2054167, 2104166],
      [258, 2016667, 2070833],
      [260, 2229167, 2279166],
      [261, 2070833, 2084999],
    ];

    for (const [band, nMin, nMax] of nrBands) {
      if (arfcn >= nMin && arfcn <= nMax) {
        const f = arfcnToMHz(arfcn);
        if (f == null) return null;
        return { band, dlMHz: +f.toFixed(2) };
      }
    }
    return null; // ARFCN not in supported bands
  }

  class LteSignal {
    constructor({
      pci,
      earfcn,
      bandwidth,
      rsrp = null,
      rsrq = null,
      sinr = null,
      rssi = null,
      ulConfigured = false,
      bandActive = false,
      dlFreqMhz = null,
      band = null
    }) {
      this.pci = pci;
      this.earfcn = earfcn;
      this.bandwidth = bandwidth;
      this.rsrp = rsrp;
      this.rsrq = rsrq;
      this.sinr = sinr;
      this.rssi = rssi;
      this.ulConfigured = ulConfigured;
      this.bandActive = bandActive;
      this.dlFreqMhz = dlFreqMhz;
      this.band = band;
    }

    static parse(netInfo) {
      const lteca = netInfo?.lteca;
      const ltecasig = netInfo?.ltecasig;
      if (!lteca) return [];

      const caEntries = lteca.split(";").filter(e => e.trim() !== "");
      const sigEntries = ltecasig ? ltecasig.split(";").filter(e => e.trim() !== "") : [];

      const signals = [];

      caEntries.forEach((entry, idx) => {
        const parts = entry.split(",").map(p => p.trim());
        if (parts.length < 5) return;

        const pci = parseInt(parts[0], 10);
        const earfcn = parseInt(parts[3], 10);
        const bandwidth = parseInt(parts[4], 10);

        let rsrp = null, rsrq = null, sinr = null, rssi = null;
        let ulConfigured = true, bandActive = true;

        if (idx === 0) {
          // primary band → values directly from netInfo
          rsrp = parseFloat(netInfo.lte_rsrp ?? null);
          rsrq = parseFloat(netInfo.lte_rsrq ?? null);
          sinr = parseFloat(netInfo.lte_snr ?? null);
          rssi = parseFloat(netInfo.lte_rssi ?? null);
        } else if (sigEntries[idx - 1]) {
          const sigParts = sigEntries[idx - 1].split(",").map(s => s.trim());
          if (sigParts.length >= 6) {
            rsrp = parseFloat(sigParts[0]);
            rsrq = parseFloat(sigParts[1]);
            sinr = parseFloat(sigParts[2]);
            rssi = parseFloat(sigParts[3]);
            ulConfigured = sigParts[4] === "1";
            bandActive  = sigParts[5] === "2";
          }
        }

        const freq = convert4gEarfcnToMhz(earfcn);

        signals.push(new LteSignal({
          pci,
          earfcn,
          bandwidth,
          rsrp,
          rsrq,
          sinr,
          rssi,
          ulConfigured,
          bandActive,
          dlFreqMhz: freq ? freq.dlMHz : null,
          band: freq ? freq.band : null
        }));
      });

      return signals;
    }

    static calculateEnodeBAndSectorId(cellId) {
      if (!cellId || isNaN(cellId)) return { eNodeB: null, sector: null };
      const id = Number(cellId);
      return {
        eNodeB: id >>> 8,
        sector: id & 0xFF
      };
    }
  }

  class NrSignal {
    constructor({
      pci,
      arfcn,
      bandwidth,
      rsrp = null,
      rsrq = null,
      sinr = null,
      rssi = null,
      ulConfigured = false,
      bandActive = false,
      dlFreqMhz = null,
      band = null
    }) {
      this.pci = pci;
      this.arfcn = arfcn;
      this.bandwidth = bandwidth;
      this.rsrp = rsrp;
      this.rsrq = rsrq;
      this.sinr = sinr;
      this.rssi = rssi;
      this.ulConfigured = ulConfigured;
      this.bandActive = bandActive;
      this.dlFreqMhz = dlFreqMhz;
      this.band = band;
    }

    static parse(netInfo) {
      const signals = [];

      // --- Primary NR cell ---
      if (netInfo.nr5g_action_channel) {
        const arfcn = parseInt(netInfo.nr5g_action_channel, 10);
        const bw = parseInt(netInfo.nr5g_bandwidth, 10);
        const pci = parseInt(netInfo.nr5g_pci, 10);

        const conv = convert5gArfcnToMhz(arfcn);

        let band = null;
        if (conv) {
          band = conv.band;
        } else if (netInfo.nr5g_action_band) {
          band = netInfo.nr5g_action_band.replace(/^n/i, ""); // strip leading "n"
        }

        signals.push(new NrSignal({
          pci,
          arfcn,
          bandwidth: bw,
          rsrp: parseFloat(netInfo.nr5g_rsrp ?? null),
          rsrq: parseFloat(netInfo.nr5g_rsrq ?? null),
          sinr: parseFloat(netInfo.nr5g_snr ?? null),
          rssi: parseFloat(netInfo.nr5g_rssi ?? null),
          ulConfigured: true,  // primary always true
          bandActive: true,    // primary always active
          dlFreqMhz: conv ? conv.dlMHz : null,
          band
        }));
      }

      // --- NR CA cells ---
      if (netInfo.nrca) {
        const caEntries = netInfo.nrca.split(";").filter(e => e.trim() !== "");
        caEntries.forEach(entry => {
          const parts = entry.split(",").map(p => p.trim());
          if (parts.length < 11) return;

          const ulConfFlag = parseInt(parts[0], 10);
          const pci = parseInt(parts[1], 10);
          const activeFlag = parseInt(parts[2], 10);
          const band = parts[3] ? "n" + parts[3] : null;
          const arfcn = parseInt(parts[4], 10);
          const bw = parseInt(parts[5], 10);

          const rsrp = parseFloat(parts[7]);
          const rsrq = parseFloat(parts[8]);
          const sinr = parseFloat(parts[9]);
          const rssi = parseFloat(parts[10]);

          const conv = convert5gArfcnToMhz(arfcn);

          signals.push(new NrSignal({
            pci,
            arfcn,
            bandwidth: bw,
            rsrp,
            rsrq,
            sinr,
            rssi,
            ulConfigured: ulConfFlag === 1, // 1 = true, 0 = false
            bandActive: activeFlag === 2,    // 2 = active, 1 = inactive
            dlFreqMhz: conv ? conv.dlMHz : null,
            band: conv ? conv.band : band
          }));
        });
      }

      return signals;
    }

    static calculateGnodeBAndSectorId(nci) {
      if (!nci || isNaN(nci)) return { gNodeB: null, sector: null };
      const id = Number(nci);
      return {
        gNodeB: id >>> 8,
        sector: id & 0xFF
      };
    }
  }

  class Signal {
    constructor() {
      this.lteSignal = [];
      this.nrSignal = [];
    }

    static parse(netInfo) {
      const signal = new Signal();

      // parse LTE
      signal.lteSignal = LteSignal.parse(netInfo);

      // parse NR
      signal.nrSignal = NrSignal.parse(netInfo);

      return signal;
    }
  }

  // --- ubus actions ---
  async function updateDeviceInfo() {
    const res = await callUbus([
      { service: "zte_nwinfo_api", method: "nwinfo_get_netinfo" },
      { service: "zwrt_bsp.thermal", method: "get_cpu_temp" },
      { service: "zwrt_mc.device.manager", method: "get_device_info" },
      { service: "zwrt_router.api", method: "router_get_status" }
    ]);

    if (Array.isArray(res) && res.length === 4) {
      const netRes = res[0];
      const tempRes = res[1];
      const devRes = res[2];
      const wanRes = res[3];
      const signal = Signal.parse(netRes.data);

      if (netRes.success && netRes.data) {
        // store latest netInfo globally
        currentNetInfo = netRes.data;

        InfoRenderer.render(
          netRes.data,
          tempRes.success ? tempRes.data : null,
          devRes.success ? devRes.data : null,
          wanRes.success ? wanRes.data : null,
          signal
        );

        highlightBearer(netRes.data.net_select);

        if (netRes.data.lte_band_lock) {
          const maskNum = BigInt(netRes.data.lte_band_lock);
          setCurrent4gMask(maskNum);
          update4gBandLockHeader(maskNum);
        }

        if (netRes.data.nr5g_sa_band_lock) {
          const activeBands = netRes.data.nr5g_sa_band_lock.split(",").map(b => b.trim());
          setCurrent5gBands(activeBands);
          update5gBandLockHeader(activeBands);
        }

        update5gCellLockUi(netRes.data);
        update4gCellLockUi(netRes.data);
      }
    }
  }

  async function setBearer(modeId) {
    return await callUbus({
      service: "zte_nwinfo_api",
      method: "nwinfo_set_netselect",
      params: { net_select: modeId }
    });
  }

  async function set4gBandLock(maskNum) {
    return await callUbus({
      service: "zte_nwinfo_api",
      method: "nwinfo_set_gwl_bandlock",
      params: { 
        is_gw_band: "0",
        gw_band_mask: "0",
        is_lte_band: "1",
        lte_band_mask: maskNum.toString() // decimal as string
      }
    });
  }

  async function set5gBandLock(bands) {
    const bandString = bands.join(",");
    return await callUbus([
      {
        service: "zte_nwinfo_api",
        method: "nwinfo_set_nrbandlock",
        params: { nr5g_type: "SA", nr5g_band: bandString }
      }
    ]);
  }

  async function lock5gCell(pci, earfcn, band) {
    const res = await callUbus({
      service: "zte_nwinfo_api",
      method: "nwinfo_lock_nr_cell",
      params: {
        lock_nr_pci: pci.toString(),
        lock_nr_earfcn: earfcn.toString(),
        lock_nr_cell_band: band.toString()
      }
    });
    return res && res.success === true;
  }

  async function lock4gCell(pci, earfcn) {
    const res = await callUbus({
      service: "zte_nwinfo_api",
      method: "nwinfo_lock_lte_cell",
      params: {
        lock_lte_pci: pci.toString(),
        lock_lte_earfcn: earfcn.toString()
      }
    });
    return res && res.success === true;
  }

  async function unlock4gCell() {
    return lock4gCell(0, 0);
  }

  // --- UI feedback overlay ---
  function showUiFeedback(success) {
    let overlay = document.getElementById("ui-feedback-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "ui-feedback-overlay";
      overlay.style.cssText = `
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 48px;
        font-weight: bold;
        z-index: 1000;
        pointer-events: none;
        display: none;
      `;
      const panelBox = document.getElementById("router-info-box");
      panelBox.style.position = "relative";
      panelBox.appendChild(overlay);
    }

    overlay.textContent = success ? "✓" : "✗";
    overlay.style.color = success ? "green" : "red";
    overlay.style.display = "block";

    setTimeout(() => {
      overlay.style.display = "none";
    }, 1000);
  }

  async function runWithUiFeedback(fn) {
    try {
      const res = await fn();
      if (!res || res.success === false) {
        showUiFeedback(false);
      } else {
        showUiFeedback(true);
      }
      updateDeviceInfo();
      return res;
    } catch (e) {
      showUiFeedback(false);
      throw e;
    }
  }

  // --- render ---
  class InfoRenderer {
    static render(netInfo, thermalInfo, deviceInfo, wanInfo, signalInfo) {
      const netTable = document.getElementById("router-info-table");
      const wanTable = document.getElementById("wan-info-table");
      const sysTable = document.getElementById("system-info-table");

      if (!netTable || !wanTable || !sysTable) return;

      this.renderNetworkInfo(netTable, netInfo, signalInfo);
      this.renderSignalInfo(netInfo, signalInfo);
      this.renderWanInfo(wanTable, wanInfo);
      this.renderDeviceInfo(sysTable, thermalInfo, deviceInfo);
    }

    static renderNetworkInfo(table, netInfo, signalInfo) {
      let bandSummary = "-";
      let totalBandwidth = 0;

      if (signalInfo) {
        const nrBands = [];
        const lteBands = [];

        if (is5gBasedNetworkType(netInfo?.network_type)) {
          signalInfo.nrSignal?.forEach(cell => {
            if (cell.band) nrBands.push(`N${cell.band}`);
            if (cell.bandwidth) totalBandwidth += cell.bandwidth;
          });
        }

        if (is4gBasedNetworkType(netInfo?.network_type)) {
          signalInfo.lteSignal?.forEach(cell => {
            if (cell.band) lteBands.push(`B${cell.band}`);
            if (cell.bandwidth) totalBandwidth += cell.bandwidth;
          });
        }

        const parts = [];
        if (nrBands.length > 0) parts.push(...nrBands);
        if (lteBands.length > 0) parts.push(...lteBands);

        if (parts.length > 0) {
          bandSummary = parts.join(" + ");
        }
      }

      let connType = netInfo.network_type || "-";
      if (connType === "SA") {
        connType = "5G SA";
      } else if (connType === "ENDC") {
        connType = "5G NSA";
      }

      let cellIdDisplay = "-";

      let nodeId = null;
      let sectorId = null;

      if (is4gBasedNetworkType(netInfo.network_type) && netInfo.cell_id) {
        const { eNodeB, sector } = LteSignal.calculateEnodeBAndSectorId(netInfo.cell_id);
        nodeId = eNodeB;
        sectorId = sector;
      } else if (netInfo.nr5g_cell_id) {
        const { gNodeB, sector } = NrSignal.calculateGnodeBAndSectorId(netInfo.nr5g_cell_id);
        nodeId = gNodeB;
        sectorId = sector;
      }

      if (nodeId != null && sectorId != null) {
        cellIdDisplay = `${toHex(nodeId, false)}<span class="cellid-sep">|</span>${toHex(sectorId, false)}`;
      }

      table.innerHTML = `
        <tr><th>Provider</th><td>${netInfo.network_provider_fullname || "-"}</td></tr>
        <tr><th>Connection</th><td>${connType}</td></tr>
        <tr><th>Bands</th><td>${bandSummary}</td></tr>
        <tr><th>BW</th><td>${totalBandwidth > 0 ? totalBandwidth + " MHz" : "-"}</td></tr>
        <tr><th>Cell ID</th><td>${cellIdDisplay}</td></tr>
      `;
    }

    static renderSignalInfo(netInfo, signalInfo) {
      const sigContainer = document.getElementById("signal-info-container");
      if (!sigContainer) return;

      sigContainer.innerHTML = "";

      function tf(val) {
        return val ? "✓" : "✗";
      }

      // --- NR signals ---
      if ((netInfo?.network_type === "SA" || netInfo?.network_type === "ENDC") &&
          signalInfo?.nrSignal?.length > 0) {
        const grid = document.createElement("div");
        grid.className = "signal-grid";

        signalInfo.nrSignal.forEach((cell, idx) => {
          const box = document.createElement("div");
          box.className = "signal-cell";
          const bandTitle = cell.band ? `N${cell.band}` : `NR Cell ${idx + 1}`;

          box.innerHTML = `
            <div class="cell-title">${bandTitle}</div>
            <table>
              <tr><th>RSRP</th><td>${cell.rsrp ?? "-"}</td></tr>
              <tr><th>RSRQ</th><td>${cell.rsrq ?? "-"}</td></tr>
              <tr><th>SINR</th><td>${cell.sinr ?? "-"}</td></tr>
              <tr><th>RSSI</th><td>${cell.rssi ?? "-"}</td></tr>
              <tr><th>PCI</th><td>${cell.pci ?? "-"}</td></tr>
              <tr><th>BW</th><td>${cell.bandwidth ? cell.bandwidth + " MHz" : "-"}</td></tr>
              <tr><th>ARFCN</th><td>${cell.arfcn ?? "-"}</td></tr>
              <tr><th>Freq</th><td>${cell.dlFreqMhz ? cell.dlFreqMhz + " MHz" : "-"}</td></tr>
              <tr><th>UL Configured</th><td>${tf(cell.ulConfigured)}</td></tr>
              <tr><th>Active</th><td>${tf(cell.bandActive)}</td></tr>
            </table>
          `;
          grid.appendChild(box);
        });

        sigContainer.appendChild(grid);
      }

      // --- LTE signals ---
      if (is4gBasedNetworkType(netInfo?.network_type) && signalInfo?.lteSignal?.length > 0) {
        const grid = document.createElement("div");
        grid.className = "signal-grid";

        signalInfo.lteSignal.forEach((cell, idx) => {
          const box = document.createElement("div");
          box.className = "signal-cell";
          const bandTitle = cell.band ? `B${cell.band}` : `Cell ${idx + 1}`;

          box.innerHTML = `
            <div class="cell-title">${bandTitle}</div>
            <table>
              <tr><th>RSRP</th><td>${cell.rsrp ?? "-"}</td></tr>
              <tr><th>RSRQ</th><td>${cell.rsrq ?? "-"}</td></tr>
              <tr><th>SINR</th><td>${cell.sinr ?? "-"}</td></tr>
              <tr><th>RSSI</th><td>${cell.rssi ?? "-"}</td></tr>
              <tr><th>PCI</th><td>${cell.pci ?? "-"}</td></tr>
              <tr><th>BW</th><td>${cell.bandwidth ? cell.bandwidth + " MHz" : "-"}</td></tr>
              <tr><th>EARFCN</th><td>${cell.earfcn ?? "-"}</td></tr>
              <tr><th>Freq</th><td>${cell.dlFreqMhz ? cell.dlFreqMhz + " MHz" : "-"}</td></tr>
              <tr><th>UL Configured</th><td>${tf(cell.ulConfigured)}</td></tr>
              <tr><th>Active</th><td>${tf(cell.bandActive)}</td></tr>
            </table>
          `;
          grid.appendChild(box);
        });

        sigContainer.appendChild(grid);
      }
    }

    static renderWanInfo(table, wanInfo) {
      let rows = "";

      if (wanInfo) {
        rows += `<tr><th>Mode</th><td>${wanInfo.mwan_wanlan1_link_mode || "-"}</td></tr>`;
        rows += `<tr><th>Status</th><td>${wanInfo.mwan_wanlan1_status || "-"}</td></tr>`;

        rows += `<tr><th>IPv4 Address</th><td>${wanInfo.mwan_wanlan1_wan_ipaddr || "-"}</td></tr>`;
        rows += `<tr><th>Netmask</th><td>${wanInfo.mwan_wanlan1_wan_netmask || "-"}</td></tr>`;
        rows += `<tr><th>Gateway</th><td>${wanInfo.mwan_wanlan1_wan_gateway || "-"}</td></tr>`;

        const dns4 = [wanInfo.mwan_wanlan1_prefer_dns_auto, wanInfo.mwan_wanlan1_standby_dns_auto]
          .filter(Boolean).join(", ");
        rows += `<tr><th>DNS</th><td>${dns4 || "-"}</td></tr>`;

        if (wanInfo.mwan_wanlan1_ipv6_wan_ipaddr && wanInfo.mwan_wanlan1_ipv6_wan_ipaddr !== "0::0") {
          rows += `<tr><th>IPv6 Address</th><td>${wanInfo.mwan_wanlan1_ipv6_wan_ipaddr}</td></tr>`;
          rows += `<tr><th>IPv6 Gateway</th><td>${wanInfo.mwan_wanlan1_ipv6_wan_gateway || "-"}</td></tr>`;

          const dns6 = [wanInfo.mwan_wanlan1_ipv6_prefer_dns_auto, wanInfo.mwan_wanlan1_ipv6_standby_dns_auto]
            .filter(Boolean).join(", ");
          rows += `<tr><th>IPv6 DNS</th><td>${dns6 || "-"}</td></tr>`;
        }
      }

      table.innerHTML = rows;
    }

    static renderDeviceInfo(table, thermalInfo, deviceInfo) {
      let rows = "";

      rows += `<tr><th>CPU Temp</th><td>${thermalInfo?.cpuss_temp ?? "-"}°C</td></tr>`;

      if (deviceInfo?.cpuinfo) {
        deviceInfo.cpuinfo
          .filter(c => c.name !== "all")
          .forEach(c => {
            const idle = parseFloat(c.idle) || 0;
            const load = Math.round(100 - idle);
            rows += `<tr><th>CPU Core ${c.name}</th><td>${load}%</td></tr>`;
          });
      }

      if (deviceInfo?.meminfo) {
        const total = parseInt(deviceInfo.meminfo.total, 10);
        const available = parseInt(deviceInfo.meminfo.avaliable, 10);
        const used = total - available;
        const percent = total > 0 ? Math.round((used / total) * 100) : 0;

        const usedMB = (used / 1024).toFixed(0);
        const totalMB = (total / 1024).toFixed(0);

        rows += `<tr><th>Memory</th><td>${usedMB}MB/${totalMB}MB (${percent}%)</td></tr>`;
      }

      if (deviceInfo?.device_uptime) {
        rows += `<tr><th>Uptime</th><td>${formatSeconds(deviceInfo.device_uptime)}</td></tr>`;
      }

      table.innerHTML = rows;
    }
  }

  function highlightBearer(current) {
    ["Only_5G","LTE_AND_5G","WL_AND_5G","Only_LTE"].forEach(mode => {
      const btn = document.getElementById("bearer-" + mode);
      if (btn) {
        if (mode === current) {
          btn.style.background = "#4CAF50";
          btn.style.color = "white";
          btn.style.fontWeight = "bold";
        } else {
          btn.style.background = "";
          btn.style.color = "";
          btn.style.fontWeight = "normal";
        }
      }
    });
  }

  // --- Update 4G Band Lock Header ---
  function update4gBandLockHeader(maskNum) {
    const activeBands = [];

    // check band bits 1..44
    for (let band = 1; band <= 44; band++) {
      if ((maskNum & get4gBandMask(band)) !== 0n) {
        activeBands.push(band);
      }
    }

    const bandList = activeBands.length > 0 ? activeBands.join(", ") : "auto";
    const header = document.getElementById("lte-band-lock-header");
    if (header) {
      header.textContent = `4G Band Lock: (${bandList})`;
    }
  }

  function update5gBandLockHeader(activeBands) {
    // Expecting activeBands as an array of strings, e.g. ["1", "3", "78"]
    const bandList = activeBands.length > 0 ? activeBands.join(", ") : "auto";

    const header = document.getElementById("nr-band-lock-header");
    if (header) {
      header.textContent = `5G Band Lock: (${bandList})`;
    }
  }

  // --- Cell lock UI updaters ---

  function update5gCellLockUi(info) {
    const lockBtn = document.getElementById("btn-lock-5g-cell");
    const title = document.getElementById("title-5g-celllock");
    if (!lockBtn || !title) return;

    lockBtn.dataset.pci = info.nr5g_pci || "<PCI>";
    lockBtn.dataset.earfcn = info.nr5g_action_channel || "<EARFCN>";
    lockBtn.dataset.band = info.nr5g_action_band
      ? info.nr5g_action_band.replace("n", "")
      : "<BAND>";

    if (info.lock_nr_cell && info.lock_nr_cell.trim() !== "" && info.lock_nr_cell !== "0,0,0") {
      title.textContent = `5G Cell Lock (${info.lock_nr_cell})`;
    } else {
      title.textContent = "5G Cell Lock";
    }
  }

  function update4gCellLockUi(info) {
    const lockBtn = document.getElementById("btn-lock-4g-cell");
    const title = document.getElementById("title-4g-celllock");
    if (!lockBtn || !title) return;

    lockBtn.dataset.pci = info.lte_pci || "<PCI>";
    lockBtn.dataset.earfcn = info.lte_action_channel || "<EARFCN>";

    if (info.lock_lte_cell && info.lock_lte_cell.trim() !== "" && info.lock_lte_cell !== "0,0") {
      title.textContent = `4G Cell Lock (${info.lock_lte_cell})`;
    } else {
      title.textContent = "4G Cell Lock";
    }
  }

  // --- Setup 4G Band Buttons ---
  function setup4gBandButtons() {
    const SUPPORTED_4G_BANDS = [1, 3, 7, 8, 20, 28, 38, 40, 41, 42, 43];

    function buildMask(bands) {
      return bands.reduce((mask, b) => mask | get4gBandMask(Number(b)), 0n);
    }

    function buildFullMask() {
      return buildMask(SUPPORTED_4G_BANDS);
    }

    function setupBandButton(btnId, bands, isAll = false, isManual = false) {
      const btn = document.getElementById(btnId);
      if (!btn) return;

      btn.addEventListener("click", async () => {
        let newMask;

        if (isAll) {
          newMask = buildFullMask();
        } else if (isManual) {
          while (true) {
            const input = prompt("Enter 4G bands (e.g. 1+3+20 or 1,3,20):");
            if (input === null) return;

            const tokens = input.split(/[\+,]/).map(t => t.trim()).filter(t => t !== "");
            if (tokens.length > 0 && tokens.every(t => /^\d+$/.test(t))) {
              newMask = buildMask(tokens);
              break;
            } else {
              alert("Invalid input. Please enter band numbers like: 1+3+20");
            }
          }
        } else {
          const arr = Array.isArray(bands) ? bands : [bands];
          newMask = buildMask(arr);
        }

        setCurrent4gMask(newMask);
        update4gBandLockHeader(newMask);
        await runWithUiFeedback(() => set4gBandLock(newMask));
      });
    }

    // Buttons
    setupBandButton("lte-band-auto", null, true);
    setupBandButton("lte-band-manual", null, false, true);

    SUPPORTED_4G_BANDS.forEach(band => {
      setupBandButton(`lte-band-b${band}`, band);
    });

    // Combo buttons
    setupBandButton("lte-band-b1b3", ["1", "3"]);
    setupBandButton("lte-band-b1b3b7", ["1", "3", "7"]);
  }

  // --- Setup 5G Band Buttons ---
  function setup5gBandButtons() {
    const FULL_5G_BANDS = ["1","3","7","8","20","28","38","40","41","75","77","78"];

    function setupBandButton(btnId, bands, isAll = false, isManual = false) {
      const btn = document.getElementById(btnId);
      if (!btn) return;

      btn.addEventListener("click", async () => {
        let newBands;

        if (isAll) {
          // All button → all bands
          newBands = [...FULL_5G_BANDS];
        } else if (isManual) {
          while (true) {
            const input = prompt("Enter 5G bands (e.g. 1+3+28 or 1,3,28):");
            if (input === null) return;

            // Split on + or , , trim spaces
            const tokens = input.split(/[\+,]/).map(t => t.trim()).filter(t => t !== "");

            // Validate: must all be numbers
            if (tokens.length > 0 && tokens.every(t => /^\d+$/.test(t))) {
              newBands = tokens;
              break;
            } else {
              alert("Invalid input. Please enter band numbers like: 1+3+28");
            }
          }
        } else {
          // Specific band(s) → exactly those bands
          newBands = Array.isArray(bands) ? bands : [bands];
        }

        setCurrent5gBands(newBands);
        update5gBandLockHeader(newBands);
        await runWithUiFeedback(() => set5gBandLock(newBands));
      });
    }

    // All + Manual
    setupBandButton("band-auto", null, true);
    setupBandButton("band-manual", null, false, true);

    // Singles
    setupBandButton("band-n1", "1");
    setupBandButton("band-n3", "3");
    setupBandButton("band-n7", "7");
    setupBandButton("band-n28", "28");
    setupBandButton("band-n78", "78");

    // Combos
    setupBandButton("band-n28n75", ["28", "75"])

    setupBandButton("band-n78n28n75", ["78", "28", "75"]);
  }

  function setupInfoCheckboxes() {
    const netChk = document.getElementById("chk-network-info");
    const wanChk = document.getElementById("chk-wan-info");
    const devChk = document.getElementById("chk-device-info");
    const sigChk = document.getElementById("chk-signal-info");

    const netSection = document.getElementById("network-info-section");
    const wanSection = document.getElementById("wan-info-section");
    const devSection = document.getElementById("device-info-section");
    const sigSection = document.getElementById("signal-info-section");

    // Load states
    netChk.checked = localStorage.getItem("ScriptCheckBoxNetworkInfo") !== "false"; // default ON
    wanChk.checked = localStorage.getItem("ScriptCheckBoxWanInfo") === "true";      // default OFF
    devChk.checked = localStorage.getItem("ScriptCheckBoxDeviceInfo") === "true";   // default OFF
    sigChk.checked = localStorage.getItem("ScriptCheckBoxSignalInfo") !== "false";  // default ON

    netSection.style.display = netChk.checked ? "block" : "none";
    wanSection.style.display = wanChk.checked ? "block" : "none";
    devSection.style.display = devChk.checked ? "block" : "none";
    sigSection.style.display = sigChk.checked ? "block" : "none";

    // Handlers
    netChk.addEventListener("change", () => {
      localStorage.setItem("ScriptCheckBoxNetworkInfo", netChk.checked);
      netSection.style.display = netChk.checked ? "block" : "none";
    });

    wanChk.addEventListener("change", () => {
      localStorage.setItem("ScriptCheckBoxWanInfo", wanChk.checked);
      wanSection.style.display = wanChk.checked ? "block" : "none";
    });

    devChk.addEventListener("change", () => {
      localStorage.setItem("ScriptCheckBoxDeviceInfo", devChk.checked);
      devSection.style.display = devChk.checked ? "block" : "none";
    });

    sigChk.addEventListener("change", () => {
      localStorage.setItem("ScriptCheckBoxSignalInfo", sigChk.checked);
      sigSection.style.display = sigChk.checked ? "block" : "none";
    });
  }

  // --- Global button blur handler ---
  function initButtonBlurHandler() {
    const panel = document.getElementById("router-info-panel");
    if (!panel) return;
    panel.addEventListener("click", (e) => {
      if (e.target && e.target.tagName === "BUTTON") {
        e.target.blur();
      }
    });
  }

  // --- UI init ---
  function initPanel() {
    const old = document.getElementById("router-info-panel");
    if (old) old.remove();

    const panel = document.createElement("div");
    panel.id = "router-info-panel";
    panel.style.cssText = "width:100%; margin-bottom:20px;";

    panel.innerHTML = `
    <div id="router-info-box" class="info-box">
      <div class="info-title">ZTE-Script-NG v${VERSION}</div>

      <!-- Network Mode -->
      <div class="section">
        <div class="section-title">Network Mode</div>
        <div class="button-row">
          <button id="bearer-Only_5G">5G SA</button>
          <button id="bearer-LTE_AND_5G">5G NSA</button>
          <button id="bearer-WL_AND_5G">4G/5G</button>
          <button id="bearer-Only_LTE">4G</button>
        </div>
      </div>

      <!-- 5G Band Lock -->
      <div class="section">
        <div id="nr-band-lock-header" class="section-title">5G Band Lock</div>
        <div class="button-row">
          <button id="band-auto">All</button>
          <button id="band-manual">Manual</button>
          <button id="band-n1">N1</button>
          <button id="band-n3">N3</button>
          <button id="band-n7">N7</button>
          <button id="band-n28">N28</button>
          <button id="band-n28n75">N28+N75</button>
          <button id="band-n78">N78</button>
          <button id="band-n78n28n75">N78+N28+N75</button>
        </div>
      </div>

      <!-- 4G Band Lock -->
      <div class="section">
        <div id="lte-band-lock-header" class="section-title">4G Band Lock</div>
        <div class="button-row">
          <button id="lte-band-auto">All</button>
          <button id="lte-band-manual">Manual</button>
          <button id="lte-band-b1">B1</button>
          <button id="lte-band-b3">B3</button>
          <button id="lte-band-b7">B7</button>
          <button id="lte-band-b8">B8</button>
          <button id="lte-band-b20">B20</button>
          <button id="lte-band-b28">B28</button>
          <button id="lte-band-b1b3">B1+B3</button>
          <button id="lte-band-b1b3b7">B1+B3+B7</button>
        </div>
      </div>

      <!-- Cell Locks -->
      <div class="section celllock-container">
        <div class="celllock-box">
          <div class="section-title" id="title-5g-celllock">5G Cell Lock</div>
          <div class="button-row">
            <button id="btn-lock-5g-cell">Enable Cell Lock</button>
            <button id="btn-revert-5g-cell">Revert Cell Lock</button>
          </div>
        </div>
        <div class="celllock-box">
          <div class="section-title" id="title-4g-celllock">4G Cell Lock</div>
          <div class="button-row">
            <button id="btn-lock-4g-cell">Enable Cell Lock</button>
            <button id="btn-revert-4g-cell">Revert Cell Lock</button>
          </div>
        </div>
      </div>

      <!-- Info Checkboxes -->
      <div class="section" id="info-checkboxes" style="text-align:center; margin-top:12px;">
        <label style="margin-right:15px;">
          <input type="checkbox" id="chk-network-info"> Show Network Info
        </label>
        <label>
          <input type="checkbox" id="chk-signal-info"> Show Signal Info
        </label>
        <label>
          <input type="checkbox" id="chk-wan-info"> Show WAN Info
        </label>
        <label>
          <input type="checkbox" id="chk-device-info"> Show Device Info
        </label>
      </div>

      <!-- Info Table -->
      <div class="info-section" id="network-info-section">
        <div class="section-title">Network Info</div>
        <table id="router-info-table" class="info-table"></table>
      </div>

      <div class="info-section" id="signal-info-section">
        <div class="section-title">Signal Info</div>
        <div id="signal-info-container"></div>
      </div>

      <div class="info-section" id="wan-info-section">
        <div class="section-title">WAN Info</div>
        <table id="wan-info-table" class="info-table"></table>
      </div>

      <div class="info-section" id="device-info-section">
        <div class="section-title">Device Info</div>
        <table id="system-info-table" class="info-table"></table>
      </div>
    </div>

    <style>
      .cellid-sep {
        opacity: 0.5;
      }
      .signal-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 12px;
        margin-top: 10px;
      }
      .signal-cell {
        border: 1px solid #eee;
        border-radius: 6px;
        background: #fafafa;
        padding: 8px;
      }
      .signal-cell table {
        width: 100%;
        border-collapse: collapse;
      }
      .signal-cell th, .signal-cell td {
        padding: 4px;
        border-bottom: 1px solid #eee;
      }
      .signal-cell th {
        text-align: left;
        font-weight: normal;
        color: #444;
        width: 50%;
      }
      .signal-cell td {
        text-align: right;
      }
      .signal-cell .cell-title {
        font-weight: bold;
        text-align: center;
        padding: 4px 0;
        margin-bottom: 6px;
        border-bottom: 1px solid #ddd;
      }
      #info-checkboxes label {
        margin-right: 15px;
      }
      .info-box {
        background:#fff;
        border:1px solid #ccc;
        border-radius:8px;
        padding:15px;
        margin:0 auto;
        max-width:700px;
        box-shadow:0 2px 5px rgba(0,0,0,0.1);
      }
      .info-title {
        font-weight:bold;
        font-size:18px;
        padding:8px 0;
        margin-bottom:12px;
        border-bottom:2px solid #ddd;
        text-align:center;
      }
      .info-section {
        margin-top: 16px;
        background: #fff;
        border: 1px solid #ddd;
        border-radius: 6px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        overflow: hidden;
      }
      .info-subtitle {
        font-weight: bold;
        font-size: 14px;
        padding: 8px 10px;
        background: #f7f7f7;
        border-bottom: 1px solid #ddd;
        text-align: center;
      }
      .section-title {
        font-weight: bold;
        font-size: 14px;
        margin-bottom: 6px;
        color: #333;
        text-align: left;
        border-bottom: 1px solid #ddd;
        padding-bottom: 2px;
      }
      .section {
        margin:16px 0;
      }
      .section-title {
        font-weight:bold;
        margin-bottom:8px;
        text-align:center;
        font-size:14px;
        color:#333;
      }
      .button-row {
        display:flex;
        flex-wrap:wrap;
        gap:6px;
        justify-content:center;
      }
      button {
        background:#f9f9f9;
        border:1px solid #ccc;
        border-radius:4px;
        padding:6px 12px;
        font-size:13px;
        cursor:pointer;
        transition:background 0.2s, color 0.2s;
      }
      button:hover {
        background:#4CAF50;
        color:#fff;
      }
      .celllock-container {
        display:flex;
        justify-content:space-between;
        gap:20px;
      }
      .celllock-box {
        flex:1;
        text-align:center;
        border:1px solid #eee;
        border-radius:6px;
        padding:10px;
        background:#fafafa;
      }
      .info-table {
        width:100%;
        border-collapse:collapse;
        margin-top:10px;
      }
      .info-table th, .info-table td {
        padding:6px;
        border-bottom:1px solid #eee;
      }
      .info-table th {
        text-align:left;
        font-weight:normal;
        color:#444;
      }
      .info-table td {
        text-align:right;
      }
    </style>
  `;

    document.body.prepend(panel);

    // bearer buttons
    document.getElementById("bearer-Only_5G").addEventListener("click", () => runWithUiFeedback(() => setBearer("Only_5G")));
    document.getElementById("bearer-LTE_AND_5G").addEventListener("click", () => runWithUiFeedback(() => setBearer("LTE_AND_5G")));
    document.getElementById("bearer-WL_AND_5G").addEventListener("click", () => runWithUiFeedback(() => setBearer("WL_AND_5G")));
    document.getElementById("bearer-Only_LTE").addEventListener("click", () => runWithUiFeedback(() => setBearer("Only_LTE")));

    // setup 4G band buttons
    setup4gBandButtons();

    // setup 5G band buttons
    setup5gBandButtons();

    // enable 5g cell lock button
    document.getElementById("btn-lock-5g-cell").addEventListener("click", async (e) => {
      const pciDefault = e.target.dataset.pci || "<PCI>";
      const earfcnDefault = e.target.dataset.earfcn || "<EARFCN>";
      const bandDefault = e.target.dataset.band || "<BAND>";
      const defaultText = `${pciDefault},${earfcnDefault},${bandDefault}`;

      while (true) {
        const input = prompt("Enter PCI,EARFCN,BAND", defaultText);
        if (input === null) return;

        const parts = input.split(",").map(s => s.trim());
        if (parts.length === 3 && parts.every(s => s !== "" && !isNaN(s))) {
          const [pci, earfcn, band] = parts;
          await runWithUiFeedback(() => lock5gCell(pci, earfcn, band));
          return;
        }

        alert("Invalid format. Please enter numbers as: PCI,EARFCN,BAND");
      }
    });

    // revert 5g cell lock button
    document.getElementById("btn-revert-5g-cell").addEventListener("click", async () => {
      if (!currentNetInfo?.lock_nr_cell || currentNetInfo.lock_nr_cell === "0,0,0") {
        alert("No 5G cell lock is currently active.");
        return;
      }

      const ok = await runWithUiFeedback(() => lock5gCell(0, 0, 0));
      if (ok) {
        alert("Reverted 5G Cell Lock. Toggle net mode or reboot the router to go back to your default Cell now.");
      }
    });

    // enable 4g cell lock button
    document.getElementById("btn-lock-4g-cell").addEventListener("click", async (e) => {
      const pciDefault = e.target.dataset.pci || "<PCI>";
      const earfcnDefault = e.target.dataset.earfcn || "<EARFCN>";
      const defaultText = `${pciDefault},${earfcnDefault}`;

      while (true) {
        const input = prompt("Enter PCI,EARFCN", defaultText);
        if (input === null) return;

        const parts = input.split(",").map(s => s.trim());
        if (parts.length === 2 && parts.every(s => s !== "" && !isNaN(s))) {
          const [pci, earfcn] = parts;
          await runWithUiFeedback(() => lock4gCell(pci, earfcn));
          return;
        }

        alert("Invalid format. Please enter numbers as: PCI,EARFCN");
      }
    });

    // revert 4g cell lock button
    document.getElementById("btn-revert-4g-cell").addEventListener("click", async () => {
      if (!currentNetInfo?.lock_lte_cell || currentNetInfo.lock_lte_cell === "0,0") {
        alert("No 4G cell lock is currently active.");
        return;
      }

      const ok = await runWithUiFeedback(() => unlock4gCell());
      if (ok) {
        alert("Reverted 4G Cell Lock. Toggle net mode or reboot the router to go back to your default Cell now.");
      }
    });

    // auto-refresh
    setInterval(updateDeviceInfo, 1000);

    // global blur handler for our panel buttons
    initButtonBlurHandler();

    // info checkboxes
    setupInfoCheckboxes();
  }

  (async () => {
    let waitingMsgShown = false;
    let interval; // will hold the timer

    async function tryInit() {
      if (await check_login()) {
        scriptMsg("Login successful, initializing panel...");
        clearInterval(interval);
        initPanel();
        return true;
      } else {
        if (!waitingMsgShown) {
          scriptMsg("Waiting for login...");
          waitingMsgShown = true;
        }
        return false;
      }
    }

    // run once immediately
    if (!(await tryInit())) {
      interval = setInterval(tryInit, 500);
    }

    showBanner();
  })();
})();
