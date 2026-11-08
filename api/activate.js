// ============================================================================
// ENDPOINT: POST /api/activate (ACTIVATE MACHINE LICENSE KEY)
// ============================================================================
const {
  verifyLicenseKey,
  createSessionToken,
  getCleanMachineId,
  formatMachineId
} = require("../lib/crypto");
const { isBlacklisted, getAllData, saveData } = require("../lib/db");

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch (_) {}
    }
    body = body || {};

    const machineId = body.machineId || req.query.machineId;
    const key = body.key || req.query.key;

    if (!machineId || !key) {
      return res.status(400).json({
        success: false,
        error: "Thiếu thông tin Mã máy (machineId) hoặc Mã kích hoạt (key)!"
      });
    }

    const blacklisted = await isBlacklisted(machineId, key);
    if (blacklisted) {
      return res.status(403).json({
        success: false,
        revoked: true,
        error:
          "Khóa kích hoạt hoặc thiết bị này đã bị thu hồi/khóa bởi Quản trị viên!"
      });
    }

    const check = verifyLicenseKey(key, machineId);
    if (!check.valid) {
      return res.status(401).json({
        success: false,
        error: check.error
      });
    }

    const formattedMid = formatMachineId(machineId);

    try {
      const db = await getAllData();
      const cleanMid = getCleanMachineId(machineId);
      const existing = db.keys[cleanMid] || {};
      db.keys[cleanMid] = {
        ...existing,
        machineId: formattedMid,
        key: check.fullKey,
        clientName: existing.clientName || "Khách hàng",
        expiry: check.expiry,
        expiryLabel: check.expiryLabel,
        lastActivatedAt: new Date().toISOString(),
        ip:
          req.headers["x-forwarded-for"] ||
          req.socket?.remoteAddress ||
          "unknown"
      };
      await saveData(db);
    } catch (e) {
      console.warn("[Activate] DB save warning:", e.message);
    }

    const token = createSessionToken(formattedMid, check.expiry);

    return res.status(200).json({
      success: true,
      message: "Kích hoạt bản quyền thiết bị thành công!",
      license: {
        active: true,
        machineId: formattedMid,
        expiry: check.expiry,
        expiryLabel: check.expiryLabel,
        key: check.fullKey
      },
      token
    });
  } catch (err) {
    console.error("[API Activate] Error:", err);
    return res.status(500).json({
      success: false,
      error: "Lỗi máy chủ: " + err.message
    });
  }
};
