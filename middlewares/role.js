// 🔐 Restrict access to only admin users for specific actions
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: "Access denied: Admins only" });
  }
  next();
};

module.exports = { requireAdmin };