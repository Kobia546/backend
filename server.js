const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Middlewares de sécurité
app.use(helmet());
app.use(cors({
  origin: '*', 
  credentials: true
}));

app.use(express.json({ 
  limit: '10mb',
  strict: false,
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      if (buf && buf.length > 0) {
        res.status(400).json({ error: 'JSON invalide dans la requête' });
        return;
      }
    }
  }
}));

app.use(express.urlencoded({ extended: true }));

// ============================================
// CONFIGURATION MYSQL OPTIMISÉE
// ============================================

const poolConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5571,
  
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
  
  connectTimeout: 20000,
  acquireTimeout: 20000,
  timeout: 30000,
  
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  
  maxIdle: 10,
  idleTimeout: 30000,
  reconnect: true,
  
  charset: 'utf8mb4',
  timezone: '+00:00',
  supportBigNumbers: true,
  bigNumberStrings: false,
  dateStrings: false,
  namedPlaceholders: false
};

const pool = mysql.createPool(poolConfig);

// ============================================
// SYSTÈME DE HEALTH CHECK
// ============================================

let isHealthy = false;
let lastHealthCheck = Date.now();
const HEALTH_CHECK_INTERVAL = 15000;

async function performHealthCheck() {
  try {
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    isHealthy = true;
    lastHealthCheck = Date.now();
    return true;
  } catch (error) {
    console.error('❌ Health check failed:', error.message);
    isHealthy = false;
    return false;
  }
}

setInterval(async () => {
  await performHealthCheck();
}, HEALTH_CHECK_INTERVAL);

// ============================================
// FONCTION DE RETRY AMÉLIORÉE
// ============================================

async function executeWithRetry(queryFn, maxRetries = 5, delayMs = 500) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      if (!isHealthy && attempt === 1) {
        await performHealthCheck();
      }
      
      return await queryFn();
      
    } catch (error) {
      lastError = error;
      
      const retryableErrors = [
        'ECONNRESET', 
        'ETIMEDOUT', 
        'ECONNREFUSED',
        'PROTOCOL_CONNECTION_LOST',
        'ER_SERVER_SHUTDOWN',
        'ER_LOCK_WAIT_TIMEOUT'
      ];
      
      const shouldRetry = retryableErrors.includes(error.code) || 
                         error.errno === -104 ||
                         error.message?.includes('Connection lost');
      
      if (!shouldRetry) {
        throw error;
      }
      
      if (attempt === maxRetries) {
        console.error(`❌ Échec après ${maxRetries} tentatives:`, error.message);
        throw error;
      }
      
      const backoffDelay = delayMs * Math.pow(1.5, attempt - 1) + Math.random() * 200;
      console.log(`⚠️ Tentative ${attempt}/${maxRetries} échouée, retry dans ${Math.round(backoffDelay)}ms...`);
      
      await new Promise(resolve => setTimeout(resolve, backoffDelay));
      
      if (attempt > 1) {
        await performHealthCheck();
      }
    }
  }
  
  throw lastError;
}

// ============================================
// WRAPPER POUR LES REQUÊTES AVEC RETRY
// ============================================

async function query(sql, params) {
  return executeWithRetry(async () => {
    return await pool.execute(sql, params);
  });
}

async function getConnection() {
  return executeWithRetry(async () => {
    return await pool.getConnection();
  });
}

// ============================================
// TEST DE CONNEXION
// ============================================

async function testConnection() {
  console.log('🔄 Test de connexion à la base de données...');
  
  try {
    const startTime = Date.now();
    const conn = await getConnection();
    const duration = Date.now() - startTime;
    
    console.log(`✅ Connecté à Nodechef en ${duration}ms`);
    
    await conn.query('SELECT 1');
    console.log('✅ Requête de test réussie');
    
    conn.release();
    isHealthy = true;
    return true;
    
  } catch (err) {
    console.error('❌ Erreur de connexion MySQL:', err.message);
    isHealthy = false;
    return false;
  }
}

// ============================================
// WARMUP AU DÉMARRAGE
// ============================================

async function warmupPool() {
  console.log('🔥 Warmup du pool de connexions...');
  
  const connections = [];
  const targetConnections = Math.min(3, poolConfig.connectionLimit);
  
  try {
    for (let i = 0; i < targetConnections; i++) {
      const conn = await getConnection();
      connections.push(conn);
      await conn.query('SELECT 1');
    }
    
    console.log(`✅ ${targetConnections} connexions pré-chargées`);
    
    for (const conn of connections) {
      conn.release();
    }
    
    return true;
  } catch (error) {
    console.error('❌ Erreur lors du warmup:', error.message);
    for (const conn of connections) {
      try { conn.release(); } catch (e) {}
    }
    return false;
  }
}

// ============================================
// MIDDLEWARE D'AUTHENTIFICATION
// ============================================

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token d\'accès requis' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const [users] = await query(
      `SELECT u.*, c.name as company_name, c.is_active as company_active 
       FROM users u 
       JOIN companies c ON u.company_id = c.id 
       WHERE u.id = ? AND u.is_active = 1 AND c.is_active = 1`,
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(403).json({ error: 'Utilisateur ou entreprise inactive' });
    }

    req.user = users[0];
    req.ip = req.ip || req.connection.remoteAddress;
    next();
    
  } catch (error) {
    console.error('Erreur authentification:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Token invalide' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ error: 'Token expiré' });
    }
    
    const dbErrors = ['ECONNRESET', 'ER_SERVER_SHUTDOWN', 'PROTOCOL_CONNECTION_LOST', 'ETIMEDOUT'];
    if (dbErrors.includes(error.code)) {
      return res.status(503).json({ 
        error: 'Service temporairement indisponible. Veuillez réessayer.',
        retryable: true 
      });
    }
    
    return res.status(500).json({ error: 'Erreur serveur' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès admin requis' });
  }
  next();
};

// ============================================
// FONCTION DE LOGGING D'ACTIVITÉ
// ============================================

const logActivity = async (companyId, userId, action, entityType = null, entityId = null, details = {}, ipAddress = null) => {
  try {
    if (!companyId) {
      console.log(`[LOG] ${action} - ${JSON.stringify(details)} - IP: ${ipAddress}`);
      return;
    }

    await query(
      `INSERT INTO activity_logs (company_id, user_id, action, entity_type, entity_id, details, ip_address) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [companyId, userId, action, entityType, entityId, JSON.stringify(details), ipAddress]
    );
  } catch (error) {
    console.error('Erreur log activité:', error);
  }
};

// ============================================
// FONCTION UTILITAIRE POUR ERREURS
// ============================================

const handleDatabaseError = (error, res, customMessage = 'Erreur serveur') => {
  console.error('Erreur base de données:', error);
  
  if (error.code === 'ECONNRESET' || error.code === 'ER_SERVER_SHUTDOWN' || error.code === 'PROTOCOL_CONNECTION_LOST') {
    return res.status(503).json({ error: 'Service de base de données temporairement indisponible. Veuillez réessayer.' });
  }
  
  if (error.code === 'ETIMEDOUT' || error.code === 'ER_LOCK_WAIT_TIMEOUT') {
    return res.status(503).json({ error: 'Timeout de la base de données. Veuillez réessayer.' });
  }
  
  if (error.code === 'ER_NO_DEFAULT_FOR_FIELD') {
    return res.status(500).json({ error: 'Erreur de configuration de base de données. Veuillez contacter l\'administrateur.' });
  }
  
  if (error.code === 'ER_DUP_ENTRY') {
    return res.status(400).json({ error: 'Cette entrée existe déjà dans la base de données.' });
  }
  
  if (error.code === 'ER_BAD_NULL_ERROR') {
    return res.status(400).json({ error: 'Valeur requise manquante.' });
  }
  
  return res.status(500).json({ error: customMessage });
};

// ===============================================
// ROUTES API - AUTHENTIFICATION
// ===============================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });
    }

    const [users] = await query(
      `SELECT u.*, c.name as company_name, c.is_active as company_active
       FROM users u 
       JOIN companies c ON u.company_id = c.id 
       WHERE u.username = ? AND u.is_active = 1 AND c.is_active = 1`,
      [username]
    );

    if (users.length === 0) {
      await logActivity(null, null, 'failed_login_attempt', 'auth', null, { username }, req.ip);
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      await logActivity(user.company_id, user.id, 'failed_login_attempt', 'auth', null, {}, req.ip);
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    await query(
      'UPDATE users SET last_login = NOW() WHERE id = ?',
      [user.id]
    );

    await logActivity(user.company_id, user.id, 'successful_login', 'auth', null, {}, req.ip);

    const token = jwt.sign(
      { 
        userId: user.id, 
        companyId: user.company_id, 
        role: user.role,
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        company_id: user.company_id,
        company_name: user.company_name
      }
    });

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur de connexion');
  }
});

// ===============================================
// ROUTES USERS/SELLERS
// ===============================================

app.post('/api/users/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, full_name, email, phone } = req.body;

    if (!username || !password || !full_name) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const [existing] = await query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const [result] = await query(
      `INSERT INTO users (company_id, username, password_hash, full_name, email, phone, role, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, 'seller', ?)`,
      [req.user.company_id, username, hashedPassword, full_name, email, phone, req.user.id]
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_created', 'user', result.insertId, 
      { username, full_name }, req.ip);

    res.json({ message: 'Vendeur créé avec succès', userId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création du vendeur');
  }
});

app.get('/api/users/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [sellers] = await query(
      `SELECT id, username, full_name, email, phone, is_active, last_login, created_at
       FROM users 
       WHERE company_id = ? AND role = 'seller'
       ORDER BY created_at DESC`,
      [req.user.company_id]
    );

    res.json(sellers);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des vendeurs');
  }
});

app.put('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, email, phone, is_active } = req.body;

    await query(
      `UPDATE users SET full_name = ?, email = ?, phone = ?, is_active = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ? AND role = 'seller'`,
      [full_name, email, phone, is_active, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_updated', 'user', id, 
      { full_name, is_active }, req.ip);

    res.json({ message: 'Vendeur modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du vendeur');
  }
});

app.delete('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    await query(
      'DELETE FROM users WHERE id = ? AND company_id = ? AND role = \'seller\'',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_deleted', 'user', id, 
      {}, req.ip);

    res.json({ message: 'Vendeur supprimé avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression du vendeur');
  }
});

// ===============================================
// ROUTES PRODUCTS
// ===============================================

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { search, category, low_stock, page = 1, limit = 50 } = req.query;
    
    let queryStr = `
      SELECT p.*, s.name as supplier_name,
             DATE(p.created_at) as creation_date
      FROM products p
      LEFT JOIN suppliers s ON p.supplier_id = s.id
      WHERE p.company_id = ?
    `;
    const params = [req.user.company_id];

    if (search) {
      queryStr += ' AND (p.name LIKE ? OR p.description LIKE ? OR p.barcode LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (category && category !== '') {
      queryStr += ' AND p.category = ?';
      params.push(category);
    }

    if (low_stock === 'true') {
      queryStr += ' AND p.current_stock <= 5';
    }

    queryStr += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [products] = await query(queryStr, params);
    res.json(products);

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des produits');
  }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, initial_stock } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    await connection.beginTransaction();

    if (barcode) {
      const [existing] = await connection.execute(
        'SELECT id FROM products WHERE company_id = ? AND barcode = ?',
        [req.user.company_id, barcode]
      );
      if (existing.length > 0) {
        throw new Error('Ce code-barres existe déjà dans votre entreprise');
      }
    }

    const purchasePrice = parseFloat(purchase_price);
    const sellingPrice = parseFloat(selling_price);
    const stockValue = parseInt(initial_stock) || 0;
    const supplierIdValue = supplier_id ? parseInt(supplier_id) : null;
    const finalCategory = category && category.trim() ? category.trim() : 'Non catégorisé';

    const [result] = await connection.execute(
      `INSERT INTO products (company_id, name, description, barcode, category, supplier_id, 
       purchase_price, selling_price, current_stock, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id, 
        name, 
        description || null, 
        barcode || null, 
        finalCategory, 
        supplierIdValue, 
        purchasePrice, 
        sellingPrice, 
        stockValue, 
        req.user.id
      ]
    );

    const productId = result.insertId;

    if (stockValue > 0) {
      await connection.execute(
        `INSERT INTO stock_movements (company_id, product_id, movement_type, quantity, 
         unit_cost, reference_type, user_id) 
         VALUES (?, ?, 'in', ?, ?, 'manual', ?)`,
        [req.user.company_id, productId, stockValue, purchasePrice, req.user.id]
      );
    }

    await connection.commit();
    
    await logActivity(req.user.company_id, req.user.id, 'product_created', 'product', productId, 
      { name, initial_stock: stockValue, category: finalCategory }, req.ip);

    res.json({ message: 'Produit créé avec succès', productId });

  } catch (error) {
    await connection.rollback();
    
    console.error('Product creation error:', error);
    
    if (error.message.includes('code-barres')) {
      res.status(400).json({ error: error.message });
    } else {
      handleDatabaseError(error, res, 'Erreur lors de la création du produit');
    }
  } finally {
    connection.release();
  }
});

app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      name, 
      description, 
      barcode, 
      category, 
      supplier_id, 
      purchase_price, 
      selling_price, 
      current_stock 
    } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const parsedPurchasePrice = parseFloat(purchase_price);
    const parsedSellingPrice = parseFloat(selling_price);
    const parsedCurrentStock = parseInt(current_stock) || 0;

    if (isNaN(parsedPurchasePrice) || parsedPurchasePrice < 0) {
      return res.status(400).json({ error: 'Prix d\'achat invalide' });
    }

    if (isNaN(parsedSellingPrice) || parsedSellingPrice < 0) {
      return res.status(400).json({ error: 'Prix de vente invalide' });
    }

    const [existing] = await query(
      'SELECT id, name FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    if (barcode && barcode.trim() !== '') {
      const [barcodeCheck] = await query(
        'SELECT id FROM products WHERE barcode = ? AND company_id = ? AND id != ?',
        [barcode.trim(), req.user.company_id, id]
      );

      if (barcodeCheck.length > 0) {
        return res.status(400).json({ error: 'Code-barres déjà utilisé par un autre produit' });
      }
    }

    const finalSupplierId = supplier_id && supplier_id !== '' ? parseInt(supplier_id) : null;
    const finalBarcode = barcode && barcode.trim() !== '' ? barcode.trim() : null;
    const finalCategory = category && category.trim() !== '' ? category.trim() : null;
    const finalDescription = description && description.trim() !== '' ? description.trim() : null;

    await query(
      `UPDATE products SET 
        name = ?, 
        description = ?, 
        barcode = ?, 
        category = ?,
        supplier_id = ?, 
        purchase_price = ?, 
        selling_price = ?, 
        current_stock = ?, 
        updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [
        name.trim(), 
        finalDescription, 
        finalBarcode, 
        finalCategory,
        finalSupplierId, 
        parsedPurchasePrice, 
        parsedSellingPrice, 
        parsedCurrentStock, 
        id, 
        req.user.company_id
      ]
    );

    await logActivity(
      req.user.company_id, 
      req.user.id, 
      'product_updated', 
      'product', 
      id,
      { name: name.trim(), old_name: existing[0].name }, 
      req.ip
    );

    res.json({ message: 'Produit modifié avec succès', product_id: id });

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du produit');
  }
});

// ✅ FIX: Autoriser suppression même avec ventes
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { id } = req.params;

    await connection.beginTransaction();

    // Récupérer le nom du produit
    const [product] = await connection.execute(
      'SELECT name FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (product.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    // Supprimer tous les liens avant de supprimer le produit
    await connection.execute(
      'DELETE FROM stock_movements WHERE product_id = ?',
      [id]
    );

    // Garder les sale_items pour historique, mais supprimer le produit
    await connection.execute(
      'DELETE FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await connection.commit();

    await logActivity(req.user.company_id, req.user.id, 'product_deleted', 'product', id, 
      { name: product[0].name }, req.ip);

    res.json({ message: 'Produit supprimé avec succès' });
  } catch (error) {
    await connection.rollback();
    handleDatabaseError(error, res, 'Erreur lors de la suppression du produit');
  } finally {
    connection.release();
  }
});

app.get('/api/products/categories', authenticateToken, async (req, res) => {
  try {
    const [categories] = await query(
      `SELECT DISTINCT category 
       FROM products 
       WHERE company_id = ? AND category IS NOT NULL AND category != ''
       ORDER BY category`,
      [req.user.company_id]
    );

    const categoryList = categories.map(row => row.category);
    res.json(categoryList);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des catégories');
  }
});

// ===============================================
// ROUTES CATEGORIES
// ===============================================

app.get('/api/categories/names', authenticateToken, async (req, res) => {
  try {
    const [categories] = await query(
      `SELECT DISTINCT category as name
       FROM products 
       WHERE company_id = ? 
         AND category IS NOT NULL 
         AND category != '' 
         AND category != 'Non catégorisé'
       ORDER BY category ASC`,
      [req.user.company_id]
    );

    const categoryNames = categories.map(row => row.name);
    if (!categoryNames.includes('Non catégorisé')) {
      categoryNames.unshift('Non catégorisé');
    }

    res.json(categoryNames);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des catégories');
  }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Nom de catégorie requis' });
    }

    const categoryName = name.trim();

    const [existing] = await query(
      'SELECT id FROM products WHERE company_id = ? AND category = ? LIMIT 1',
      [req.user.company_id, categoryName]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Cette catégorie existe déjà' });
    }

    await logActivity(req.user.company_id, req.user.id, 'category_created', 'category', null, 
      { name: categoryName }, req.ip);

    res.json({ message: 'Catégorie créée avec succès', name: categoryName });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création de la catégorie');
  }
});

// ===============================================
// ROUTES SALES
// ===============================================

app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { limit = 10, page = 1, start_date, end_date } = req.query;
    
    let queryStr = `
      SELECT s.*, 
             u.full_name as seller_name,
             COALESCE(item_counts.items_count, 0) as items_count
      FROM sales s
      LEFT JOIN users u ON s.seller_id = u.id
      LEFT JOIN (
        SELECT sale_id, COUNT(*) as items_count
        FROM sale_items
        GROUP BY sale_id
      ) item_counts ON s.id = item_counts.sale_id
      WHERE s.company_id = ?
    `;
    
    const params = [req.user.company_id];
    
    if (req.user.role !== 'admin') {
      queryStr += ' AND s.seller_id = ?';
      params.push(req.user.id);
    }
    
    if (start_date) {
      queryStr += ' AND DATE(s.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      queryStr += ' AND DATE(s.created_at) <= ?';
      params.push(end_date);
    }
    
    queryStr += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [sales] = await query(queryStr, params);
    
    for (let sale of sales) {
      const [items] = await query(
        'SELECT * FROM sale_items WHERE sale_id = ?',
        [sale.id]
      );
      sale.items = items;
    }

    res.json(sales);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des ventes');
  }
});

app.post('/api/sales', authenticateToken, async (req, res) => {
  const connection = await getConnection();

  try {
    const { items, customer_name, customer_phone, payment_method, discount = 0 } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Aucun article dans la vente' });
    }

    await connection.beginTransaction();

    let subtotal = 0;
    let totalProfit = 0;
    const saleNumber = `SALE-${Date.now()}-${req.user.id}`;
    const saleItems = [];

    for (const item of items) {
      const [products] = await connection.execute(
        'SELECT current_stock, purchase_price, selling_price, name FROM products WHERE id = ? AND company_id = ?',
        [item.product_id, req.user.company_id]
      );

      if (products.length === 0) {
        throw new Error(`Produit ${item.product_id} non trouvé`);
      }

      const product = products[0];
      
      saleItems.push({
        name: product.name,
        quantity: item.quantity,
        unit_price: product.selling_price
      });

      if (product.current_stock < item.quantity) {
        throw new Error(`Stock insuffisant pour ${product.name}`);
      }

      const lineTotal = product.selling_price * item.quantity;
      const lineProfit = (product.selling_price - product.purchase_price) * item.quantity;

      subtotal += lineTotal;
      totalProfit += lineProfit;
    }

    const totalAmount = subtotal - discount;

    const [saleResult] = await connection.execute(
      `INSERT INTO sales (company_id, sale_number, customer_name, customer_phone,
       subtotal, discount, total_amount, total_profit, payment_method, seller_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        saleNumber,
        customer_name || null,
        customer_phone || null,
        subtotal,
        discount,
        totalAmount,
        totalProfit,
        payment_method || 'cash',
        req.user.id
      ]
    );

    const saleId = saleResult.insertId;

    for (const item of items) {
      const [products] = await connection.execute(
        'SELECT name, purchase_price, selling_price FROM products WHERE id = ?',
        [item.product_id]
      );

      const product = products[0];
      const lineTotal = product.selling_price * item.quantity;
      const lineProfit = (product.selling_price - product.purchase_price) * item.quantity;

      await connection.execute(
        `INSERT INTO sale_items (sale_id, product_id, product_name, quantity,
         unit_price, unit_cost, line_total, line_profit)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          saleId,
          item.product_id,
          product.name,
          item.quantity,
          product.selling_price,
          product.purchase_price,
          lineTotal,
          lineProfit
        ]
      );

      await connection.execute(
        `UPDATE products
         SET current_stock = current_stock - ?
         WHERE id = ? AND company_id = ?`,
        [item.quantity, item.product_id, req.user.company_id]
      );

      await connection.execute(
        `INSERT INTO stock_movements
         (company_id, product_id, movement_type, quantity, unit_cost, reference_type, reference_id, user_id)
         VALUES (?, ?, 'out', ?, ?, 'sale', ?, ?)`,
        [
          req.user.company_id,
          item.product_id,
          item.quantity,
          product.purchase_price,
          saleId,
          req.user.id
        ]
      );
    }

    await connection.commit();

    await logActivity(
      req.user.company_id,
      req.user.id,
      'sale_completed',
      'sale',
      saleId,
      { 
        saleNumber, 
        totalAmount, 
        itemCount: items.length,
        items: saleItems,
        customerName: customer_name || null,
        paymentMethod: payment_method || 'cash'
      },
      req.ip
    );

    res.json({
      message: 'Vente enregistrée avec succès',
      saleId,
      saleNumber,
      totalAmount,
      totalProfit
    });

  } catch (error) {
    await connection.rollback();

    if (error.message.includes('Stock insuffisant') || error.message.includes('non trouvé')) {
      return res.status(400).json({ error: error.message });
    } else {
      handleDatabaseError(error, res, 'Erreur lors de l\'enregistrement de la vente');
    }

  } finally {
    connection.release();
  }
});

// ===============================================
// ROUTES SUPPLIERS
// ===============================================

app.get('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const [suppliers] = await query(
      'SELECT * FROM suppliers WHERE company_id = ? ORDER BY name',
      [req.user.company_id]
    );
    res.json(suppliers);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des fournisseurs');
  }
});

app.post('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const { name, contact_person, phone, email, address } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Nom du fournisseur requis' });
    }

    const [result] = await query(
      `INSERT INTO suppliers (company_id, name, contact_person, phone, email, address) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, name, contact_person, phone, email, address]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_created', 'supplier', result.insertId, 
      { name }, req.ip);

    res.json({ message: 'Fournisseur créé avec succès', supplierId: result.insertId, id: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création du fournisseur');
  }
});

app.put('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, contact_person, phone, email, address } = req.body;

    await query(
      `UPDATE suppliers SET name = ?, contact_person = ?, phone = ?, email = ?, address = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [name, contact_person, phone, email, address, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_updated', 'supplier', id, 
      { name }, req.ip);

    res.json({ message: 'Fournisseur modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du fournisseur');
  }
});

app.delete('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await query(
      'DELETE FROM suppliers WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_deleted', 'supplier', id, 
      {}, req.ip);

    res.json({ message: 'Fournisseur supprimé avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression du fournisseur');
  }
});

// ===============================================
// ROUTES SUPPLIER ORDERS (DETTES FOURNISSEURS)
// ===============================================

// ✅ FIX: Route spécifique pour dettes soldées (AVANT les routes génériques)
app.get('/api/supplier-orders/paid', authenticateToken, async (req, res) => {
  try {
    const [orders] = await query(
      `SELECT so.*, s.name as supplier_name 
       FROM supplier_orders so
       LEFT JOIN suppliers s ON so.supplier_id = s.id
       WHERE so.company_id = ? AND so.status = 'paid'
       ORDER BY so.updated_at DESC
       LIMIT 200`,
      [req.user.company_id]
    );
    
    console.log(`✅ Found ${orders.length} paid orders for company ${req.user.company_id}`);
    res.json(orders);
  } catch (error) {
    console.error('Error fetching paid orders:', error);
    handleDatabaseError(error, res, 'Erreur lors de la récupération des dettes soldées');
  }
});

app.get('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await query(
      `SELECT so.*, s.name as supplier_name 
       FROM supplier_orders so
       LEFT JOIN suppliers s ON so.supplier_id = s.id
       WHERE so.company_id = ? 
       ORDER BY so.due_date ASC, so.created_at DESC`,
      [req.user.company_id]
    );
    res.json(orders);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des commandes fournisseurs');
  }
});

app.post('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const { supplier_id, product_name, amount, purchase_date, due_date, payment_method } = req.body;
    
    if (!supplier_id || !product_name || !amount) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const [result] = await query(
      `INSERT INTO supplier_orders (company_id, supplier_id, product_name, amount, remaining_amount, paid_amount, purchase_date, due_date, payment_method, status)
       VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 'pending')`,
      [req.user.company_id, supplier_id, product_name, amount, amount, purchase_date, due_date, payment_method]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_created', 'supplier_order', result.insertId,
      { product_name, amount }, req.ip);

    res.json({ message: 'Commande fournisseur créée avec succès', orderId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création de la commande fournisseur');
  }
});

// ✅ FIX: Paiement partiel fournisseur
app.post('/api/supplier-orders/:id/payments', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { id } = req.params;
    const { amount, payment_date, payment_method, note } = req.body;

    console.log(`💰 Payment request for order ${id}:`, { amount, payment_date, payment_method });

    if (!amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Montant invalide' });
    }

    await connection.beginTransaction();

    const [orders] = await connection.execute(
      'SELECT * FROM supplier_orders WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (orders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    const order = orders[0];
    const paymentAmount = parseFloat(amount);
    const currentRemaining = parseFloat(order.remaining_amount || order.amount);
    const currentPaid = parseFloat(order.paid_amount || 0);

    console.log(`📊 Order state:`, { currentRemaining, currentPaid, paymentAmount });

    if (paymentAmount > currentRemaining + 0.01) { // Tolérance pour arrondis
      await connection.rollback();
      return res.status(400).json({ 
        error: `Montant supérieur au restant. Maximum: ${currentRemaining.toFixed(2)} FCFA` 
      });
    }

    // Enregistrer le paiement
    await connection.execute(
      `INSERT INTO supplier_order_payments (order_id, payment_amount, payment_date, payment_method, note, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [id, paymentAmount, payment_date || new Date().toISOString().split('T')[0], payment_method || 'cash', note, req.user.id]
    );

    const newPaidAmount = currentPaid + paymentAmount;
    const newRemainingAmount = Math.max(0, currentRemaining - paymentAmount);
    const newStatus = newRemainingAmount <= 0.01 ? 'paid' : 'pending';

    console.log(`✅ New state:`, { newPaidAmount, newRemainingAmount, newStatus });

    await connection.execute(
      `UPDATE supplier_orders 
       SET paid_amount = ?, remaining_amount = ?, status = ?, updated_at = NOW()
       WHERE id = ?`,
      [newPaidAmount, newRemainingAmount, newStatus, id]
    );

    await connection.commit();
    
    await logActivity(req.user.company_id, req.user.id, 'supplier_order_payment_added', 'supplier_order', id,
      { amount: paymentAmount, remaining: newRemainingAmount, status: newStatus }, req.ip);
    
    res.json({ 
      message: 'Paiement enregistré avec succès', 
      paid_amount: newPaidAmount,
      remaining_amount: newRemainingAmount,
      status: newStatus
    });

  } catch (error) {
    await connection.rollback();
    console.error('Erreur paiement fournisseur:', error);
    handleDatabaseError(error, res, 'Erreur lors de l\'enregistrement du paiement');
  } finally {
    connection.release();
  }
});

app.get('/api/supplier-orders/:id/payments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [payments] = await query(
      `SELECT sop.*, u.full_name as created_by_name
       FROM supplier_order_payments sop
       LEFT JOIN users u ON sop.created_by = u.id
       WHERE sop.order_id = ?
       ORDER BY sop.payment_date DESC, sop.created_at DESC`,
      [id]
    );
    
    res.json(payments);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération de l\'historique des paiements');
  }
});

app.put('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    await query(
      `UPDATE supplier_orders SET status = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [status, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_status_updated', 'supplier_order', id,
      { status }, req.ip);

    res.json({ message: 'Statut de la commande modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du statut');
  }
});

app.delete('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { id } = req.params;

    await connection.beginTransaction();

    // Supprimer l'historique des paiements
    await connection.execute(
      'DELETE FROM supplier_order_payments WHERE order_id = ?',
      [id]
    );

    // Supprimer la commande
    await connection.execute(
      'DELETE FROM supplier_orders WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await connection.commit();

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_deleted', 'supplier_order', id,
      {}, req.ip);

    res.json({ message: 'Commande fournisseur supprimée avec succès' });
  } catch (error) {
    await connection.rollback();
    handleDatabaseError(error, res, 'Erreur lors de la suppression de la commande');
  } finally {
    connection.release();
  }
});

// ===============================================
// ROUTES EXPENSES
// ===============================================

app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const [expenses] = await query(
      `SELECT * FROM expenses 
       WHERE company_id = ? 
       ORDER BY expense_date DESC, created_at DESC`,
      [req.user.company_id]
    );
    res.json(expenses);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des dépenses');
  }
});

app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, category, expense_date } = req.body;
    
    if (!description || !amount) {
      return res.status(400).json({ error: 'Description et montant requis' });
    }

    const [result] = await query(
      `INSERT INTO expenses (company_id, description, amount, category, expense_date, created_by) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, description, amount, category || 'Autre', expense_date, req.user.id]
    );

    await logActivity(req.user.company_id, req.user.id, 'expense_created', 'expense', result.insertId, 
      { description, amount }, req.ip);

    res.json({ message: 'Dépense créée avec succès', expenseId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création de la dépense');
  }
});

app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { description, amount, category, expense_date } = req.body;

    await query(
      `UPDATE expenses SET description = ?, amount = ?, category = ?, expense_date = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [description, amount, category, expense_date, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'expense_updated', 'expense', id, 
      { description, amount }, req.ip);

    res.json({ message: 'Dépense modifiée avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification de la dépense');
  }
});

app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await query(
      'DELETE FROM expenses WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'expense_deleted', 'expense', id, 
      {}, req.ip);

    res.json({ message: 'Dépense supprimée avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression de la dépense');
  }
});

// ===============================================
// ROUTES BANK DEPOSITS
// ===============================================

app.get('/api/bank-deposits', authenticateToken, async (req, res) => {
  try {
    const [deposits] = await query(
      `SELECT bd.*, u.full_name as created_by_name
       FROM bank_deposits bd
       LEFT JOIN users u ON bd.created_by = u.id
       WHERE bd.company_id = ? 
       ORDER BY bd.deposit_date DESC, bd.created_at DESC`,
      [req.user.company_id]
    );
    res.json(deposits);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des versements banque');
  }
});

app.post('/api/bank-deposits', authenticateToken, async (req, res) => {
  try {
    const { amount, bank_name, account_number, deposit_date, reference, notes } = req.body;
    
    if (!amount || !bank_name || !deposit_date) {
      return res.status(400).json({ error: 'Montant, banque et date requis' });
    }

    const [result] = await query(
      `INSERT INTO bank_deposits (company_id, amount, bank_name, account_number, deposit_date, reference, notes, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, amount, bank_name, account_number, deposit_date, reference, notes, req.user.id]
    );

    await logActivity(req.user.company_id, req.user.id, 'bank_deposit_created', 'bank_deposit', result.insertId, 
      { bank_name, amount }, req.ip);

    res.json({ message: 'Versement banque créé avec succès', depositId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création du versement banque');
  }
});

app.put('/api/bank-deposits/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, bank_name, account_number, deposit_date, reference, notes } = req.body;

    await query(
      `UPDATE bank_deposits 
       SET amount = ?, bank_name = ?, account_number = ?, deposit_date = ?, 
           reference = ?, notes = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [amount, bank_name, account_number, deposit_date, reference, notes, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'bank_deposit_updated', 'bank_deposit', id, 
      { bank_name, amount }, req.ip);

    res.json({ message: 'Versement banque modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du versement banque');
  }
});

app.delete('/api/bank-deposits/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await query(
      'DELETE FROM bank_deposits WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'bank_deposit_deleted', 'bank_deposit', id, 
      {}, req.ip);

    res.json({ message: 'Versement banque supprimé avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression du versement banque');
  }
});

// ===============================================
// ROUTES CLIENTS
// ===============================================

app.get('/api/clients', authenticateToken, async (req, res) => {
  try {
    const [clients] = await query(
      `SELECT * FROM clients 
       WHERE company_id = ? 
       ORDER BY created_at DESC`,
      [req.user.company_id]
    );
    res.json(clients);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des clients');
  }
});

app.post('/api/clients', authenticateToken, async (req, res) => {
  try {
    const { name, phone, address, business_type } = req.body;
    
    if (!name || !phone) {
      return res.status(400).json({ error: 'Nom et téléphone requis' });
    }

    const [result] = await query(
      `INSERT INTO clients (company_id, name, phone, address, business_type, created_by) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, name, phone, address, business_type || 'particulier', req.user.id]
    );

    await logActivity(req.user.company_id, req.user.id, 'client_created', 'client', result.insertId, 
      { name, phone, business_type }, req.ip);

    res.json({ message: 'Client créé avec succès', clientId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création du client');
  }
});

app.put('/api/clients/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, address, business_type } = req.body;

    await query(
      `UPDATE clients SET name = ?, phone = ?, address = ?, business_type = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [name, phone, address, business_type || 'particulier', id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'client_updated', 'client', id, 
      { name, phone, business_type }, req.ip);

    res.json({ message: 'Client modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du client');
  }
});

app.delete('/api/clients/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await query(
      'DELETE FROM clients WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'client_deleted', 'client', id, 
      {}, req.ip);

    res.json({ message: 'Client supprimé avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression du client');
  }
});

// ===============================================
// ROUTES CLIENT ORDERS
// ===============================================

app.get('/api/client-orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await query(
      `SELECT co.*, c.name as client_name, c.phone as client_phone, c.address as client_address
       FROM client_orders co
       JOIN clients c ON co.client_id = c.id
       WHERE co.company_id = ? 
       ORDER BY 
         CASE WHEN co.status = 'pending' THEN 0 ELSE 1 END,
         co.due_date ASC, 
         co.created_at DESC`,
      [req.user.company_id]
    );

    for (let order of orders) {
      const [items] = await query(
        `SELECT coi.*, p.name as product_name, p.selling_price as unit_price
         FROM client_order_items coi
         LEFT JOIN products p ON coi.product_id = p.id
         WHERE coi.order_id = ?`,
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des commandes clients');
  }
});

app.post('/api/client-orders', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { client_id, items, total_amount, advance_payment, remaining_amount, due_date } = req.body;
    
    if (!client_id || !items || items.length === 0) {
      return res.status(400).json({ error: 'Client et produits requis' });
    }

    await connection.beginTransaction();

    const orderNumber = `CMD-${Date.now()}-${req.user.id}`;
    
    const [orderResult] = await connection.execute(
      `INSERT INTO client_orders (company_id, client_id, order_number, total_amount, 
       advance_payment, remaining_amount, due_date, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, client_id, orderNumber, total_amount, advance_payment || 0, 
       remaining_amount, due_date, req.user.id]
    );

    const orderId = orderResult.insertId;

    for (const item of items) {
      const [product] = await connection.execute(
        'SELECT name, selling_price FROM products WHERE id = ? AND company_id = ?',
        [item.product_id, req.user.company_id]
      );

      if (product.length === 0) {
        throw new Error(`Produit ${item.product_id} non trouvé`);
      }

      await connection.execute(
        `INSERT INTO client_order_items (order_id, product_id, product_name, quantity, unit_price, line_total) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [orderId, item.product_id, product[0].name, item.quantity, product[0].selling_price, 
         product[0].selling_price * item.quantity]
      );
    }

    await connection.commit();

    await logActivity(req.user.company_id, req.user.id, 'client_order_created', 'client_order', orderId, 
      { orderNumber, total_amount, itemCount: items.length }, req.ip);

    res.json({ message: 'Commande client créée avec succès', orderId, orderNumber });

  } catch (error) {
    await connection.rollback();
    
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ error: error.message });
    } else {
      handleDatabaseError(error, res, 'Erreur lors de la création de la commande client');
    }
  } finally {
    connection.release();
  }
});

app.put('/api/client-orders/:id', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { id } = req.params;
    const { status, remaining_amount, payment_amount, payment_method } = req.body;

    const validStatuses = ['pending', 'completed', 'cancelled'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ 
        error: `Status invalide. Status autorisés: ${validStatuses.join(', ')}` 
      });
    }

    await connection.beginTransaction();

    const [currentOrder] = await connection.execute(
      'SELECT * FROM client_orders WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (currentOrder.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    const order = currentOrder[0];
    
    let updateFields = [];
    let updateValues = [];
    
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
    }
    
    if (remaining_amount !== undefined && remaining_amount !== null) {
      updateFields.push('remaining_amount = ?');
      updateValues.push(Math.max(0, parseFloat(remaining_amount)));
      
      const totalAmount = parseFloat(order.total_amount);
      const newRemainingAmount = Math.max(0, parseFloat(remaining_amount));
      const newAdvancePayment = totalAmount - newRemainingAmount;
      
      updateFields.push('advance_payment = ?');
      updateValues.push(Math.max(0, newAdvancePayment));
    }
    
    if (payment_amount && parseFloat(payment_amount) > 0) {
      const currentAdvance = parseFloat(order.advance_payment || 0);
      const newAdvancePayment = currentAdvance + parseFloat(payment_amount);
      const totalAmount = parseFloat(order.total_amount);
      const newRemainingAmount = Math.max(0, totalAmount - newAdvancePayment);
      
      updateFields.push('advance_payment = ?');
      updateValues.push(newAdvancePayment);
      
      updateFields.push('remaining_amount = ?');
      updateValues.push(newRemainingAmount);
      
      const newStatus = newRemainingAmount <= 0 ? 'completed' : 'pending';
      if (!updateFields.some(field => field.startsWith('status'))) {
        updateFields.push('status = ?');
        updateValues.push(newStatus);
      }
      
      await connection.execute(
        `INSERT INTO client_order_payments (order_id, payment_amount, payment_method, payment_date, created_by) 
         VALUES (?, ?, ?, NOW(), ?)`,
        [id, payment_amount, payment_method || 'cash', req.user.id]
      );
    }
    
    updateFields.push('updated_at = NOW()');
    
    if (updateFields.length > 1) {
      const queryStr = `UPDATE client_orders SET ${updateFields.join(', ')} WHERE id = ? AND company_id = ?`;
      updateValues.push(id, req.user.company_id);
      
      await connection.execute(queryStr, updateValues);
    }

    await connection.commit();

    await logActivity(req.user.company_id, req.user.id, 'client_order_updated', 'client_order', id, 
      { status, payment_amount, remaining_amount }, req.ip);

    res.json({ 
      message: 'Commande mise à jour avec succès',
      status: status,
      remaining_amount: remaining_amount
    });

  } catch (error) {
    await connection.rollback();
    console.error('Error updating client order:', error);
    
    handleDatabaseError(error, res, 'Erreur lors de la mise à jour de la commande');
  } finally {
    connection.release();
  }
});

app.delete('/api/client-orders/:id', authenticateToken, async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { id } = req.params;

    await connection.beginTransaction();

    await connection.execute(
      'DELETE FROM client_order_items WHERE order_id = ?',
      [id]
    );

    await connection.execute(
      'DELETE FROM client_orders WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await connection.commit();

    await logActivity(req.user.company_id, req.user.id, 'client_order_deleted', 'client_order', id, 
      {}, req.ip);

    res.json({ message: 'Commande client supprimée avec succès' });
  } catch (error) {
    await connection.rollback();
    handleDatabaseError(error, res, 'Erreur lors de la suppression de la commande');
  } finally {
    connection.release();
  }
});

app.get('/api/client-orders/:id/payments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [payments] = await query(
      `SELECT cop.*, u.full_name as created_by_name
       FROM client_order_payments cop
       LEFT JOIN users u ON cop.created_by = u.id
       WHERE cop.order_id = ?
       ORDER BY cop.payment_date DESC`,
      [id]
    );

    res.json(payments);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération de l\'historique des paiements');
  }
});

// ===============================================
// ROUTES REPORTS (ADMIN)
// ===============================================

app.get('/api/reports/sellers-performance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let queryStr = `
      SELECT 
        u.id as seller_id,
        u.full_name as seller_name,
        COALESCE(sales_stats.total_sales, 0) as total_sales,
        COALESCE(sales_stats.total_revenue, 0) as total_revenue,
        COALESCE(sales_stats.avg_sale_amount, 0) as avg_sale_amount,
        COALESCE(sales_stats.total_profit, 0) as total_profit
      FROM users u
      LEFT JOIN (
        SELECT 
          seller_id,
          COUNT(*) as total_sales,
          SUM(total_amount) as total_revenue,
          AVG(total_amount) as avg_sale_amount,
          SUM(total_profit) as total_profit
        FROM sales s
        WHERE s.company_id = ?
    `;
    
    const params = [req.user.company_id, req.user.company_id];
    
    if (start_date && end_date) {
      queryStr += ' AND s.created_at BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }
    
    queryStr += `
        GROUP BY seller_id
      ) sales_stats ON u.id = sales_stats.seller_id
      WHERE u.company_id = ? AND u.role = 'seller'
      ORDER BY total_revenue DESC
    `;

    const [performance] = await query(queryStr, params);
    res.json(performance);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des performances vendeurs');
  }
});

app.get('/api/reports/activity-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, action, user, search, start_date, end_date } = req.query;
    
    let queryStr = `
      SELECT al.*, u.full_name as user_name
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.company_id = ?
    `;
    
    const params = [req.user.company_id];
    
    if (search) {
      queryStr += ' AND (al.action LIKE ? OR al.details LIKE ? OR u.full_name LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    
    if (action) {
      queryStr += ' AND al.action LIKE ?';
      params.push(`%${action}%`);
    }
    
    if (user) {
      queryStr += ' AND u.full_name LIKE ?';
      params.push(`%${user}%`);
    }
    
    if (start_date) {
      queryStr += ' AND DATE(al.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      queryStr += ' AND DATE(al.created_at) <= ?';
      params.push(end_date);
    }
    
    queryStr += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [logs] = await query(queryStr, params);
    res.json(logs);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des logs d\'activité');
  }
});

app.get('/api/reports/company-stats', authenticateToken, async (req, res) => {
  try {
    const { period = '30' } = req.query;

    if (req.user.role === 'admin') {
      const [stats] = await query(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM users WHERE company_id = ? AND role = 'seller' AND is_active = 1) as active_sellers,
          (SELECT COUNT(*) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= 5) as low_stock_products,
          (SELECT COUNT(*) FROM suppliers WHERE company_id = ?) as total_suppliers,
          (SELECT COUNT(*) FROM supplier_orders WHERE company_id = ? AND status = 'pending') as pending_supplier_orders,
          (SELECT COALESCE(SUM(remaining_amount), 0) FROM supplier_orders WHERE company_id = ? AND status = 'pending') as pending_supplier_amount,
          (SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE company_id = ? AND expense_date >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_expenses
      `, [
        req.user.company_id, req.user.company_id, req.user.company_id, period,
        req.user.company_id, period, req.user.company_id, period, req.user.company_id,
        req.user.company_id, req.user.company_id, req.user.company_id, req.user.company_id, period
      ]);

      res.json(stats[0]);
    } else {
      const [stats] = await query(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM sales WHERE company_id = ? AND seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= 5) as low_stock_products
      `, [
        req.user.company_id, 
        req.user.company_id, req.user.id, period,
        req.user.company_id, req.user.id, period,
        req.user.company_id, req.user.id, period,
        req.user.company_id
      ]);

      res.json({
        ...stats[0],
        active_sellers: 1,
        total_suppliers: 0,
        pending_supplier_orders: 0,
        pending_supplier_amount: 0,
        recent_expenses: 0
      });
    }

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des statistiques');
  }
});

// ===============================================
// ROUTES DEBUG
// ===============================================

app.get('/api/debug/user-info', authenticateToken, async (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      company_id: req.user.company_id
    },
    timestamp: new Date().toISOString()
  });
});

// ===============================================
// MIDDLEWARE ERREURS GLOBAL
// ===============================================

app.use((error, req, res, next) => {
  console.error('Erreur non gérée:', error);
  
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Données JSON invalides dans la requête' });
  }
  
  res.status(500).json({ error: 'Erreur serveur interne' });
});

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

// ===============================================
// DÉMARRAGE DU SERVEUR
// ===============================================

const startServer = async () => {
  try {
    console.log('🚀 Démarrage du serveur...\n');
    
    const connectionOk = await testConnection();
    if (!connectionOk) {
      console.error('❌ Impossible de se connecter à la base de données');
      console.log('⏳ Nouvelle tentative dans 5 secondes...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      const retryOk = await testConnection();
      if (!retryOk) {
        throw new Error('Échec de connexion à la base de données après 2 tentatives');
      }
    }
    
    await warmupPool();
    await performHealthCheck();
    
    app.listen(port, () => {
      console.log('\n' + '='.repeat(50));
      console.log(`✅ Serveur démarré avec succès !`);
      console.log(`🌐 Port: ${port}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
      console.log(`💾 Base de données: ${isHealthy ? '✅ Connectée' : '⚠️ Vérification en cours'}`);
      console.log('='.repeat(50) + '\n');
    });
    
  } catch (error) {
    console.error('\n❌ Erreur fatale au démarrage:', error.message);
    console.error('🔄 Le serveur va s\'arrêter...\n');
    process.exit(1);
  }
};

process.on('SIGINT', async () => {
  console.log('\n🔄 Arrêt du serveur...');
  try {
    await pool.end();
    console.log('✅ Connexions fermées');
  } catch (error) {
    console.error('Erreur lors de la fermeture:', error);
  }
  process.exit(0);
});

startServer();