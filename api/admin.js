// ============================================================================
// ENDPOINT: GET/POST /api/admin (ADMIN DASHBOARD - GENERATE / LOCK / DELETE)
// ============================================================================
const {
  generateKeyForMachine,
  verifyAdminPassword,
  getCleanMachineId,
  formatMachineId,
  formatExpiryLabel
} = require("../lib/crypto");
const { getAllData, saveData } = require("../lib/db");

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Admin-Password"
  );

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

    const password =
      body.password || req.headers["x-admin-password"] || req.query.password;
    if (!verifyAdminPassword(password)) {
      return res
        .status(401)
        .json({ success: false, error: "Mật khẩu Quản trị viên không chính xác!" });
    }

    const action = body.action || req.query.action || "list";
    const db = await getAllData();

    if (action === "generate") {
      const machineId = body.machineId;
      const expiry = body.expiry || "LIFETIME";
      const clientName = body.clientName || "Khách hàng";

      const cleanMid = getCleanMachineId(machineId);
      if (!cleanMid) {
        return res
          .status(400)
          .json({ success: false, error: "Thiếu Mã máy (machineId) hợp lệ!" });
      }

      const formattedMid = formatMachineId(cleanMid);
      const key = generateKeyForMachine(formattedMid, expiry);
      const expiryLabel = formatExpiryLabel(expiry);

      db.keys[cleanMid] = {
        ...(db.keys[cleanMid] || {}),
        machineId: formattedMid,
        key,
        clientName,
        expiry,
        expiryLabel,
        createdAt: new Date().toISOString()
      };
      delete db.blacklist[cleanMid];
      await saveData(db);

      return res.status(200).json({
        success: true,
        key,
        machineId: formattedMid,
        clientName,
        expiry,
        expiryLabel
      });
    }

    if (action === "revoke") {
      const target = getCleanMachineId(body.target);
      if (!target) {
        return res
          .status(400)
          .json({ success: false, error: "Thiếu mã máy cần khóa!" });
      }
      db.blacklist[target] = {
        revokedAt: new Date().toISOString(),
        reason: body.reason || "Bị khóa bởi Admin Đường Thọ"
      };
      await saveData(db);
      return res
        .status(200)
        .json({ success: true, message: `Đã khóa ${target} thành công!` });
    }

    if (action === "unrevoke") {
      const target = getCleanMachineId(body.target);
      delete db.blacklist[target];
      await saveData(db);
      return res
        .status(200)
        .json({ success: true, message: `Đã mở khóa ${target} thành công!` });
    }

    if (action === "delete") {
      const target = getCleanMachineId(body.target);
      delete db.keys[target];
      delete db.blacklist[target];
      await saveData(db);
      return res
        .status(200)
        .json({ success: true, message: `Đã xóa ${target} thành công!` });
    }

    if (action === "restore") {
      const backupData = body.backupData;
      if (!backupData || typeof backupData !== "object") {
        return res
          .status(400)
          .json({ success: false, error: "Dữ liệu backup không hợp lệ!" });
      }
      db.keys = Object.assign({}, db.keys, backupData.keys || {});
      db.blacklist = Object.assign({}, db.blacklist, backupData.blacklist || {});
      await saveData(db);
      return res
        .status(200)
        .json({ success: true, message: "Đã khôi phục dữ liệu thành công!" });
    }

    return res.status(200).json({
      success: true,
      data: db
    });
  } catch (err) {
    console.error("[API Admin] Error:", err);
    return res.status(500).json({ success: false, error: err.message });
  }
};
