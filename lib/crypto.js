// ============================================================================
// CRYPTO & LICENSE VERIFICATION MODULE (GHOSTDEVICE PRO - VERCEL BACKEND)
// ============================================================================
const crypto = require("crypto");

const GHOST_SECRET =
  process.env.GHOST_SECRET || "DUONG_THO_GHOST_PRO_2026_@#888_PROTECT";
const ADMIN_PASSWORD_SHA256 =
  process.env.ADMIN_PASSWORD_SHA256 ||
  "7da2673580a1bf1174ef5ff8b24b318d12be96144900a0d69276a51c431f7292";

function verifyAdminPassword(inputPwd) {
  if (!inputPwd || typeof inputPwd !== "string") return false;
  if (process.env.ADMIN_PASSWORD && inputPwd === process.env.ADMIN_PASSWORD) {
    return true;
  }
  const h = crypto.createHash("sha256").update(inputPwd.trim()).digest("hex");
  return h === ADMIN_PASSWORD_SHA256;
}

function hmacSha256(message, secret = GHOST_SECRET) {
  return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

function getCleanMachineId(machineId) {
  if (!machineId) return "";
  return String(machineId)
    .trim()
    .replace(/[^A-Z0-9]/gi, "")
    .replace(/^GD/i, "")
    .toUpperCase();
}

function formatMachineId(machineId) {
  const clean = getCleanMachineId(machineId);
  if (clean.length === 12) {
    return `GD-${clean.slice(0, 4)}-${clean.slice(4, 8)}-${clean.slice(8, 12)}`;
  }
  return String(machineId || "").trim().toUpperCase();
}

function computeLicenseSignature(expiry, cleanMachineId) {
  const payload = `${expiry.toUpperCase()}:${cleanMachineId.toUpperCase()}`;
  return hmacSha256(payload, GHOST_SECRET).substring(0, 8).toUpperCase();
}

function generateKeyForMachine(machineId, expiry = "LIFETIME") {
  const cleanId = getCleanMachineId(machineId);
  let exp = String(expiry || "LIFETIME").trim().toUpperCase();
  if (exp !== "LIFETIME" && !/^\d{8}$/.test(exp)) {
    exp = "LIFETIME";
  }
  const sig = computeLicenseSignature(exp, cleanId);
  return `GDK-${exp}-${cleanId}-${sig}`;
}

function formatExpiryLabel(expiry) {
  if (expiry === "LIFETIME") return "Vĩnh viễn";
  if (/^\d{8}$/.test(expiry)) {
    const y = expiry.substring(0, 4);
    const m = expiry.substring(4, 6);
    const d = expiry.substring(6, 8);
    return `${d}/${m}/${y}`;
  }
  return expiry;
}

function verifyLicenseKey(keyString, targetMachineId) {
  if (!keyString || typeof keyString !== "string") {
    return { valid: false, error: "Vui lòng nhập mã kích hoạt!" };
  }

  const cleanInput = keyString.trim().toUpperCase();
  const parts = cleanInput.split("-");

  if (parts.length !== 4 || parts[0] !== "GDK") {
    return {
      valid: false,
      error: "Định dạng mã kích hoạt không đúng (Mẫu: GDK-LIFETIME-...)"
    };
  }

  const expiry = parts[1];
  const keyMachine = parts[2];
  const keySig = parts[3];

  const currentCleanMachine = getCleanMachineId(targetMachineId);

  if (keyMachine !== currentCleanMachine) {
    return {
      valid: false,
      error: "Mã kích hoạt này không dành cho thiết bị này!"
    };
  }

  const expectedSig = computeLicenseSignature(expiry, keyMachine);
  if (keySig !== expectedSig) {
    return { valid: false, error: "Chữ ký mã kích hoạt không hợp lệ!" };
  }

  let expiryLabel = "Vĩnh viễn";
  if (expiry !== "LIFETIME") {
    if (!/^\d{8}$/.test(expiry)) {
      return {
        valid: false,
        error: "Thời hạn trong mã kích hoạt không hợp lệ!"
      };
    }
    const y = parseInt(expiry.substring(0, 4), 10);
    const m = parseInt(expiry.substring(4, 6), 10) - 1;
    const d = parseInt(expiry.substring(6, 8), 10);
    const expDate = new Date(y, m, d, 23, 59, 59);
    const now = new Date();
    expiryLabel = `${String(d).padStart(2, "0")}/${String(m + 1).padStart(2, "0")}/${y}`;

    if (now.getTime() > expDate.getTime()) {
      return {
        valid: false,
        error: `Mã kích hoạt đã hết hạn vào ngày ${expiryLabel}!`
      };
    }
  }

  return {
    valid: true,
    expiry,
    expiryLabel,
    cleanMachineId: keyMachine,
    fullKey: cleanInput
  };
}

function createSessionToken(machineId, expiry) {
  const issuedAt = Date.now();
  const payload = `${machineId}|${expiry}|${issuedAt}`;
  const sig = hmacSha256(payload, GHOST_SECRET).substring(0, 16);
  return Buffer.from(`${payload}|${sig}`).toString("base64");
}

module.exports = {
  GHOST_SECRET,
  verifyAdminPassword,
  hmacSha256,
  getCleanMachineId,
  formatMachineId,
  formatExpiryLabel,
  computeLicenseSignature,
  generateKeyForMachine,
  verifyLicenseKey,
  createSessionToken
};
