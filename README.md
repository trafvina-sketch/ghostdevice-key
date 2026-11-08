# GhostDevice Pro - Cloud License Server (Vercel)

Hệ thống máy chủ quản lý bản quyền theo mã phần cứng (1 Key = 1 Máy) cho tiện ích **Đường Thọ GhostDevice Pro**.

- **Endpoints**:
  - `POST /api/activate`: Kích hoạt key bản quyền theo `machineId` (`GD-XXXX-XXXX-XXXX`).
  - `GET /api/check`: Tự động đồng bộ bản quyền giữa mọi Profile Chrome trên cùng 1 máy tính.
  - `GET/POST /api/admin`: API quản trị tạo key, khóa/mở khóa, xóa và backup/restore JSON.
