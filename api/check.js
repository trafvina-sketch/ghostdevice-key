// ============================================================================
// ENDPOINT: GET/POST /api/check (CROSS-PROFILE MACHINE LICENSE SYNC)
// ============================================================================
const {
  verifyLicenseKey,
  createSessionToken,
  getCleanMachineId,
  formatMachineId
} = require("../lib/crypto");
const { isBlacklisted, getAllData } = require("../lib/db");

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
    if (!machineId) {
      return res.status(400).json({
        success: false,
        activated: false,
        error: "Thiếu thông tin Mã máy (machineId)!"
      });
    }

    const cleanMid = getCleanMachineId(machineId);
    const formattedMid = formatMachineId(machineId);
    const db = await getAllData();
    const record = db.keys ? db.keys[cleanMid] : null;

    if (!record || !record.key) {
      const revokedOnly = await isBlacklisted(machineId, "");
      if (revokedOnly) {
        return res.status(200).json({
          success: true,
          activated: false,
          revoked: true,
          machineId: formattedMid,
          error: "Thiết bị này đã bị khóa bởi Quản trị viên!"
        });
      }
      return res.status(200).json({
        success: true,
        activated: false,
        machineId: formattedMid,
        message: "Thiết bị chưa được kích hoạt trên hệ thống"
      });
    }

    const blacklisted = await isBlacklisted(machineId, record.key);
    if (blacklisted) {
      return res.status(200).json({
        success: true,
        activated: false,
        revoked: true,
        machineId: formattedMid,
        error:
          "Khóa kích hoạt hoặc thiết bị này đã bị thu hồi bởi Quản trị viên!"
      });
    }

    const check = verifyLicenseKey(record.key, machineId);
    if (!check.valid) {
      return res.status(200).json({
        success: true,
        activated: false,
        expired: true,
        machineId: formattedMid,
        reason: check.error,
        error: check.error
      });
    }

    const token = createSessionToken(formattedMid, check.expiry);

    return res.status(200).json({
      success: true,
      activated: true,
      message: "Thiết bị hợp lệ, đã tự động đồng bộ bản quyền!",
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
    console.error("[API Check] Error:", err);
    return res.status(500).json({
      success: false,
      activated: false,
      error: "Lỗi máy chủ: " + err.message
    });
  }
};
