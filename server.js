const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Middleware de validation générale pour les requêtes POST/PUT
function validateRequestData(req, res, next) {
  try {
    // Nettoyer les chaînes de caractères
    if (req.body) {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
          req.body[key] = req.body[key].trim();
        }
      }
    }
    next();
  } catch (error) {
    res.status(400).json({ error: 'Données de requête invalides' });
  }
}

// CORRECTION: Déplacer les middlewares dans le bon ordre
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Appliquer le middleware de validation APRÈS express.json()
app.use('/api', validateRequestData);

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'inventory_system',
};

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5571,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    ca: fs.readFileSync('isrgrootx1.pem')  // certificat TLS
  }
});

// Test de connexion
async function testConnection() {
  try {
    const conn = await pool.getConnection();
    console.log('✅ Connecté à MySQL Stackhero avec SSL !');
    conn.release();
  } catch (err) {
    console.error('❌ Erreur MySQL :', err.message);
  }
}

testConnection();

// Middleware d'authentification
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token d\'accès requis' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const [users] = await pool.execute(
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
    return res.status(403).json({ error: 'Token invalide' });
  }
};

// Middleware admin
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès admin requis' });
  }
  next();
};

// Fonction de logging d'activité
const logActivity = async (companyId, userId, action, entityType = null, entityId = null, details = {}, ipAddress = null) => {
  try {
    if (!companyId) {
      console.log(`[LOG] ${action} - ${JSON.stringify(details)} - IP: ${ipAddress}`);
      return;
    }

    await pool.execute(
      `INSERT INTO activity_logs (company_id, user_id, action, entity_type, entity_id, details, ip_address) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [companyId, userId, action, entityType, entityId, JSON.stringify(details), ipAddress]
    );
  } catch (error) {
    console.error('Erreur log activité:', error);
  }
};

app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, current_stock, min_stock_alert } = req.body;

    // Vérifiez que les champs obligatoires sont présents
    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Les champs obligatoires sont manquants' });
    }

    // Validation des prix et stocks
    const parsedPurchasePrice = parseFloat(purchase_price);
    const parsedSellingPrice = parseFloat(selling_price);
    const parsedCurrentStock = parseInt(current_stock) || 0;
    const parsedMinStockAlert = parseInt(min_stock_alert) || 5;

    // Vérifiez que les prix sont dans une plage acceptable
    if (isNaN(parsedPurchasePrice) || parsedPurchasePrice < 0 || parsedPurchasePrice > 99999999.99) {
      return res.status(400).json({ error: 'Prix d\'achat invalide (doit être entre 0 et 99999999.99)' });
    }

    if (isNaN(parsedSellingPrice) || parsedSellingPrice < 0 || parsedSellingPrice > 99999999.99) {
      return res.status(400).json({ error: 'Prix de vente invalide (doit être entre 0 et 99999999.99)' });
    }

    if (isNaN(parsedCurrentStock) || parsedCurrentStock < 0 || parsedCurrentStock > 2147483647) {
      return res.status(400).json({ error: 'Stock invalide' });
    }

    // Vérifiez que le produit appartient à l'entreprise
    const [existing] = await pool.execute(
      'SELECT id FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    // Vérifiez l'unicité du code-barres s'il est fourni et différent de l'actuel
    if (barcode) {
      const [existingBarcode] = await pool.execute(
        'SELECT id FROM products WHERE barcode = ? AND company_id = ? AND id != ?',
        [barcode.trim(), req.user.company_id, id]
      );

      if (existingBarcode.length > 0) {
        return res.status(400).json({ error: 'Ce code-barres est déjà utilisé par un autre produit' });
      }
    }

    // Mettre à jour le produit
    await pool.execute(
      `UPDATE products
       SET name = ?, description = ?, barcode = ?, category = ?,
           supplier_id = ?, purchase_price = ?, selling_price = ?,
           current_stock = ?, min_stock_alert = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [
        name.trim(),
        description ? description.trim() : null,
        barcode ? barcode.trim() : null,
        category ? category.trim() : null,
        supplier_id || null,
        parsedPurchasePrice,
        parsedSellingPrice,
        parsedCurrentStock,
        parsedMinStockAlert,
        id,
        req.user.company_id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'product_updated', 'product', id,
      { name: name.trim() }, req.ip);

    res.json({ message: 'Produit modifié avec succès' });
  } catch (error) {
    console.error('Erreur modification produit:', error);

    // Messages d'erreur plus spécifiques
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Ce code-barres est déjà utilisé.' });
    }

    res.status(500).json({ error: 'Erreur lors de la modification du produit' });
  }
});

app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const productId = parseInt(id);
    const companyId = parseInt(req.user.company_id);

    if (isNaN(productId) || isNaN(companyId)) {
      return res.status(400).json({ error: 'ID invalide' });
    }

    // Vérifiez que le produit appartient à l'entreprise
    const [product] = await pool.execute(
      `SELECT p.name, COUNT(si.id) as sale_count
       FROM products p
       LEFT JOIN sale_items si ON p.id = si.product_id
       WHERE p.id = ? AND p.company_id = ?
       GROUP BY p.id, p.name`,
      [productId, companyId]
    );

    if (product.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    if (product[0].sale_count > 0) {
      return res.status(400).json({ error: 'Impossible de supprimer un produit ayant des ventes associées' });
    }

    // Suppression du produit
    const [deleteResult] = await pool.execute(
      'DELETE FROM products WHERE id = ? AND company_id = ?',
      [productId, companyId]
    );

    if (deleteResult.affectedRows === 0) {
      return res.status(404).json({ error: 'Produit non trouvé ou déjà supprimé' });
    }

    await logActivity(companyId, req.user.id, 'product_deleted', 'product', productId,
      { name: product[0].name }, req.ip);

    res.json({ message: 'Produit supprimé avec succès' });
  } catch (error) {
    console.error('Erreur suppression produit:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du produit', details: error.message });
  }
});


// Fonction utilitaire pour valider les données numériques
function validateNumericInput(value, fieldName, min = 0, max = 99999999.99) {
  const parsed = parseFloat(value);
  
  if (isNaN(parsed)) {
    throw new Error(`${fieldName} doit être un nombre valide`);
  }
  
  if (parsed < min || parsed > max) {
    throw new Error(`${fieldName} doit être entre ${min} et ${max}`);
  }
  
  return parsed;
}

// ===============================================
// ROUTES API
// ===============================================

// Authentification
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });
    }

    const [users] = await pool.execute(
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

    // Mettre à jour la dernière connexion
    await pool.execute(
      'UPDATE users SET last_login = NOW() WHERE id = ?',
      [user.id]
    );

    // Logger la connexion réussie
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
    console.error('Erreur de connexion:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===============================================
// ROUTE DASHBOARD - CORRECTION MAJEURE
// ===============================================

app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    console.log('[DEBUG] Dashboard request for company:', req.user.company_id, 'user:', req.user.id, 'role:', req.user.role);
    
    // CORRECTION: Requêtes spécifiques selon le rôle
    if (req.user.role === 'admin') {
      // Pour l'admin : statistiques globales de l'entreprise
      const [dashboardStats] = await pool.execute(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM users WHERE company_id = ? AND role = 'seller' AND is_active = 1) as active_sellers,
          (SELECT COUNT(*) FROM sales WHERE company_id = ? AND DATE(created_at) = CURDATE()) as today_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND DATE(created_at) = CURDATE()) as today_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND DATE(created_at) = CURDATE()) as today_profit,
          (SELECT COUNT(*) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= COALESCE(min_stock_alert, 5)) as low_stock_products,
          (SELECT COUNT(*) FROM suppliers WHERE company_id = ?) as total_suppliers,
          (SELECT COUNT(*) FROM supplier_orders WHERE company_id = ? AND status = 'pending') as pending_supplier_orders,
          (SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE company_id = ? AND DATE(expense_date) >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_expenses
      `, [
        req.user.company_id, req.user.company_id, req.user.company_id, 
        req.user.company_id, req.user.company_id, req.user.company_id,
        req.user.company_id, req.user.company_id, req.user.company_id,
        req.user.company_id, req.user.company_id, req.user.company_id
      ]);

      // Récupérer les ventes récentes de tous les vendeurs
      const [recentSales] = await pool.execute(`
        SELECT s.*, u.full_name as seller_name
        FROM sales s
        LEFT JOIN users u ON s.seller_id = u.id
        WHERE s.company_id = ?
        ORDER BY s.created_at DESC
        LIMIT 10
      `, [req.user.company_id]);

      res.json({
        stats: {
          ...dashboardStats[0],
          recent_sales: dashboardStats[0].month_sales,
          recent_revenue: dashboardStats[0].month_revenue,
          recent_profit: dashboardStats[0].month_profit
        },
        recentSales,
        userRole: 'admin'
      });

    } else {
      // Pour les vendeurs : seulement leurs propres statistiques
      const [sellerStats] = await pool.execute(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM sales WHERE seller_id = ? AND DATE(created_at) = CURDATE()) as today_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE seller_id = ? AND DATE(created_at) = CURDATE()) as today_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE seller_id = ? AND DATE(created_at) = CURDATE()) as today_profit,
          (SELECT COUNT(*) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as month_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= COALESCE(min_stock_alert, 5)) as low_stock_products
      `, [
        req.user.company_id, 
        req.user.id, req.user.id, req.user.id,
        req.user.id, req.user.id, req.user.id,
        req.user.company_id
      ]);

      // Récupérer seulement les ventes de ce vendeur
      const [myRecentSales] = await pool.execute(`
        SELECT s.*, u.full_name as seller_name
        FROM sales s
        LEFT JOIN users u ON s.seller_id = u.id
        WHERE s.seller_id = ?
        ORDER BY s.created_at DESC
        LIMIT 10
      `, [req.user.id]);

      res.json({
        stats: {
          ...sellerStats[0],
          recent_sales: sellerStats[0].month_sales,
          recent_revenue: sellerStats[0].month_revenue,
          recent_profit: sellerStats[0].month_profit
        },
        recentSales: myRecentSales,
        userRole: 'seller'
      });
    }

  } catch (error) {
    console.error('Erreur dashboard:', error);
    res.status(500).json({ error: 'Erreur lors du chargement du dashboard' });
  }
});

// ===============================================
// ROUTES PRODUITS - CORRECTION
// ===============================================

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { search, category, low_stock, page = 1, limit = 50 } = req.query;
    
    console.log('[DEBUG] Products request params:', { search, category, low_stock, page, limit });
    console.log('[DEBUG] User company_id:', req.user.company_id);
    
    const pageInt = Math.max(1, parseInt(page) || 1);
    const limitInt = Math.min(1000, Math.max(1, parseInt(limit) || 50));
    const offsetInt = (pageInt - 1) * limitInt;
    
    let query = `
      SELECT p.*, s.name as supplier_name
      FROM products p
      LEFT JOIN suppliers s ON p.supplier_id = s.id
      WHERE p.company_id = ?
    `;
    
    const params = [req.user.company_id];

    if (search) {
      query += ' AND (p.name LIKE ? OR p.description LIKE ? OR p.barcode LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (category && category !== 'all') {
      query += ' AND p.category = ?';
      params.push(category);
    }

    if (low_stock === 'true') {
      query += ' AND p.current_stock <= COALESCE(p.min_stock_alert, 5)';
    }

    query += ` ORDER BY p.created_at DESC LIMIT ${limitInt} OFFSET ${offsetInt}`;
    
    console.log('[DEBUG] Final products query:', query);
    console.log('[DEBUG] Final products params:', params);

    const [products] = await pool.execute(query, params);
    
    // Compter le total pour la pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM products p
      WHERE p.company_id = ?
    `;
    
    const countParams = [req.user.company_id];
    
    if (search) {
      countQuery += ' AND (p.name LIKE ? OR p.description LIKE ? OR p.barcode LIKE ?)';
      countParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (category && category !== 'all') {
      countQuery += ' AND p.category = ?';
      countParams.push(category);
    }

    if (low_stock === 'true') {
      countQuery += ' AND p.current_stock <= COALESCE(p.min_stock_alert, 5)';
    }

    const [countResult] = await pool.execute(countQuery, countParams);
    
    console.log('[DEBUG] Products found:', products.length);
    console.log('[DEBUG] Total products:', countResult[0].total);

    res.json({
      data: products,
      pagination: {
        page: pageInt,
        limit: limitInt,
        total: countResult[0].total,
        totalPages: Math.ceil(countResult[0].total / limitInt)
      }
    });

  } catch (error) {
    console.error('Erreur récupération produits:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, current_stock, min_stock_alert } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Les champs obligatoires sont manquants' });
    }

    // Validation des prix pour éviter l'erreur "Out of range"
    const parsedPurchasePrice = parseFloat(purchase_price);
    const parsedSellingPrice = parseFloat(selling_price);
    const parsedCurrentStock = parseInt(current_stock) || 0;
    const parsedMinStockAlert = parseInt(min_stock_alert) || 5;

    // Vérifier que les prix sont dans une plage acceptable
    if (parsedPurchasePrice < 0 || parsedPurchasePrice > 99999999.99) {
      return res.status(400).json({ error: 'Prix d\'achat invalide (doit être entre 0 et 99999999.99)' });
    }

    if (parsedSellingPrice < 0 || parsedSellingPrice > 99999999.99) {
      return res.status(400).json({ error: 'Prix de vente invalide (doit être entre 0 et 99999999.99)' });
    }

    if (parsedCurrentStock < 0 || parsedCurrentStock > 2147483647) {
      return res.status(400).json({ error: 'Stock invalide' });
    }

    // Vérifier l'unicité du code-barres s'il est fourni
    if (barcode) {
      const [existingBarcode] = await pool.execute(
        'SELECT id FROM products WHERE barcode = ? AND company_id = ?',
        [barcode.trim(), req.user.company_id]
      );

      if (existingBarcode.length > 0) {
        return res.status(400).json({ error: 'Ce code-barres existe déjà' });
      }
    }

    const [result] = await pool.execute(
      `INSERT INTO products (company_id, name, description, barcode, category, supplier_id, 
       purchase_price, selling_price, current_stock, min_stock_alert, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        name.trim(),
        description ? description.trim() : null,
        barcode ? barcode.trim() : null,
        category ? category.trim() : null,
        supplier_id || null,
        parsedPurchasePrice,
        parsedSellingPrice,
        parsedCurrentStock,
        parsedMinStockAlert,
        req.user.id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'product_created', 'product', result.insertId, 
      { name: name.trim() }, req.ip);

    res.status(201).json({ 
      message: 'Produit ajouté avec succès', 
      productId: result.insertId 
    });

  } catch (error) {
    console.error('Erreur ajout produit:', error);
    
    // Messages d'erreur plus spécifiques
    if (error.code === 'ER_NO_DEFAULT_FOR_FIELD') {
      return res.status(400).json({ error: 'Erreur de configuration de la base de données. Contactez l\'administrateur.' });
    }
    
    if (error.code === 'ER_WARN_DATA_OUT_OF_RANGE') {
      return res.status(400).json({ error: 'Une des valeurs numériques est hors limite. Vérifiez les prix et quantités.' });
    }
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Ce code-barres existe déjà.' });
    }

    res.status(500).json({ error: 'Erreur lors de l\'ajout du produit' });
  }
});

// ===============================================
// ROUTES VENTES - CORRECTIONS
// ===============================================

app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { limit = 10, page = 1, start_date, end_date } = req.query;
    
    console.log('[DEBUG] Sales request params:', { limit, page, start_date, end_date, user_role: req.user.role });
    
    const pageInt = Math.max(1, parseInt(page) || 1);
    const limitInt = Math.min(1000, Math.max(1, parseInt(limit) || 10));
    const offsetInt = (pageInt - 1) * limitInt;
    
    let whereClause = 's.company_id = ?';
    const params = [req.user.company_id];
    
    // CORRECTION: Si vendeur, ne voir que ses propres ventes
    if (req.user.role === 'seller') {
      whereClause += ' AND s.seller_id = ?';
      params.push(req.user.id);
    }
    
    if (start_date) {
      whereClause += ' AND DATE(s.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      whereClause += ' AND DATE(s.created_at) <= ?';
      params.push(end_date);
    }
    
    const query = `
      SELECT s.*, u.full_name as seller_name,
             COUNT(si.id) as items_count
      FROM sales s
      LEFT JOIN users u ON s.seller_id = u.id
      LEFT JOIN sale_items si ON s.id = si.sale_id
      WHERE ${whereClause}
      GROUP BY s.id 
      ORDER BY s.created_at DESC 
      LIMIT ${limitInt} OFFSET ${offsetInt}
    `;

    console.log('[DEBUG] Sales query:', query);
    console.log('[DEBUG] Sales params:', params);

    const [sales] = await pool.execute(query, params);
    
    // Get sale items for each sale
    for (let sale of sales) {
      const [items] = await pool.execute(
        'SELECT * FROM sale_items WHERE sale_id = ?',
        [sale.id]
      );
      sale.items = items;
    }

    console.log('[DEBUG] Sales found:', sales.length, 'for user role:', req.user.role);
    res.json(sales);
  } catch (error) {
    console.error('Erreur récupération ventes:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { items, customer_name, customer_phone, payment_method, discount = 0 } = req.body;

    console.log('[DEBUG] Création vente - Items reçus:', items);

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Aucun article dans la vente' });
    }

    // Validation du discount
    const validatedDiscount = parseFloat(discount) || 0;
    if (validatedDiscount < 0 || validatedDiscount > 99999999.99) {
      return res.status(400).json({ error: 'Remise invalide' });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      let subtotal = 0;
      let totalProfit = 0;
      const saleNumber = `SALE-${Date.now()}-${req.user.id}`;
      const saleItems = []; // Pour stocker les détails des items

      console.log('[DEBUG] Numéro de vente généré:', saleNumber);

      // ÉTAPE 1: Vérification et verrouillage des stocks
      for (const item of items) {
        const quantity = parseFloat(item.quantity);
        if (isNaN(quantity) || quantity <= 0) {
          throw new Error(`Quantité invalide pour l'article ${item.product_id}`);
        }
        
        console.log('[DEBUG] Vérification produit ID:', item.product_id, 'Quantité:', quantity);
        
        // Récupérer les données du produit avec verrouillage
        const [products] = await connection.execute(
          'SELECT current_stock, purchase_price, selling_price, name FROM products WHERE id = ? AND company_id = ? FOR UPDATE',
          [item.product_id, req.user.company_id]
        );

        if (products.length === 0) {
          throw new Error(`Produit ${item.product_id} non trouvé`);
        }

        const product = products[0];
        console.log('[DEBUG] Produit trouvé:', product.name, 'Stock actuel:', product.current_stock);
        
        if (product.current_stock < quantity) {
          throw new Error(`Stock insuffisant pour ${product.name}. Stock disponible: ${product.current_stock}, demandé: ${quantity}`);
        }

        const lineTotal = product.selling_price * quantity;
        const lineProfit = (product.selling_price - product.purchase_price) * quantity;
        
        subtotal += lineTotal;
        totalProfit += lineProfit;

        // Stocker les détails pour création ultérieure
        saleItems.push({
          product_id: item.product_id,
          product_name: product.name,
          quantity: quantity,
          unit_price: product.selling_price,
          unit_cost: product.purchase_price,
          line_total: lineTotal,
          line_profit: lineProfit
        });

        console.log('[DEBUG] Item calculé:', {
          name: product.name,
          quantity,
          unitPrice: product.selling_price,
          lineTotal,
          lineProfit
        });
      }

      const totalAmount = subtotal - validatedDiscount;

      if (totalAmount < 0) {
        throw new Error('Le montant total ne peut pas être négatif');
      }

      console.log('[DEBUG] Totaux calculés:', {
        subtotal,
        discount: validatedDiscount,
        totalAmount,
        totalProfit
      });

      // ÉTAPE 2: Créer la vente
      const [saleResult] = await connection.execute(
        `INSERT INTO sales (company_id, sale_number, customer_name, customer_phone, 
         subtotal, discount, total_amount, total_profit, payment_method, seller_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.company_id, 
          saleNumber, 
          customer_name ? customer_name.trim() : null, 
          customer_phone ? customer_phone.trim() : null, 
          subtotal, 
          validatedDiscount, 
          totalAmount, 
          totalProfit, 
          payment_method || 'cash', 
          req.user.id
        ]
      );

      const saleId = saleResult.insertId;
      console.log('[DEBUG] Vente créée avec ID:', saleId);

      // ÉTAPE 3: Ajouter les items et mettre à jour le stock
      for (const saleItem of saleItems) {
        // Insérer l'item de vente
        await connection.execute(
          `INSERT INTO sale_items (sale_id, product_id, product_name, quantity, 
           unit_price, unit_cost, line_total, line_profit) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            saleId, 
            saleItem.product_id, 
            saleItem.product_name, 
            saleItem.quantity,
            saleItem.unit_price, 
            saleItem.unit_cost, 
            saleItem.line_total, 
            saleItem.line_profit
          ]
        );

        console.log('[DEBUG] Item de vente ajouté pour:', saleItem.product_name);

        // CORRECTION: Une seule mise à jour du stock, atomique
        const [updateResult] = await connection.execute(
          'UPDATE products SET current_stock = current_stock - ? WHERE id = ? AND company_id = ?',
          [saleItem.quantity, saleItem.product_id, req.user.company_id]
        );

        if (updateResult.affectedRows === 0) {
          throw new Error(`Impossible de mettre à jour le stock pour ${saleItem.product_name}`);
        }

        console.log('[DEBUG] Stock mis à jour pour', saleItem.product_name, '- Quantité retirée:', saleItem.quantity);
      }

      // ÉTAPE 4: Log d'activité
      try {
        await logActivity(
          req.user.company_id, 
          req.user.id, 
          'sale_completed', 
          'sale', 
          saleId,
          { 
            saleNumber, 
            totalAmount, 
            itemCount: saleItems.length,
            customerName: customer_name 
          }, 
          req.ip
        );
      } catch (logError) {
        console.warn('[WARNING] Erreur lors du log d\'activité:', logError.message);
        // Ne pas faire échouer la vente pour un problème de log
      }

      await connection.commit();
      console.log('[DEBUG] Transaction commitée avec succès pour vente:', saleNumber);
      
      res.json({ 
        message: 'Vente enregistrée avec succès', 
        saleId, 
        saleNumber,
        totalAmount, 
        totalProfit,
        itemCount: saleItems.length
      });

    } catch (error) {
      await connection.rollback();
      console.error('[ERROR] Rollback transaction - Erreur:', error.message);
      throw error;
    } finally {
      connection.release();
    }

  } catch (error) {
    console.error('[ERROR] Erreur création vente:', error);
    console.error('[ERROR] Stack trace:', error.stack);
    
    // Messages d'erreur spécifiques pour le frontend
    if (error.message.includes('Stock insuffisant')) {
      return res.status(400).json({ error: error.message });
    }
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ error: error.message });
    }
    if (error.message.includes('invalide') || error.message.includes('négatif')) {
      return res.status(400).json({ error: error.message });
    }

    // Erreur générique pour les autres cas
    res.status(500).json({ 
      error: 'Erreur lors de la création de la vente',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// BONUS: Fonction utilitaire pour vérifier les stocks avant vente (optionnel)
app.post('/api/sales/check-stock', authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;
    
    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Aucun article à vérifier' });
    }

    const stockCheck = [];
    
    for (const item of items) {
      const quantity = parseFloat(item.quantity);
      
      if (isNaN(quantity) || quantity <= 0) {
        stockCheck.push({
          product_id: item.product_id,
          available: false,
          error: 'Quantité invalide'
        });
        continue;
      }

      const [products] = await pool.execute(
        'SELECT id, name, current_stock, selling_price FROM products WHERE id = ? AND company_id = ?',
        [item.product_id, req.user.company_id]
      );

      if (products.length === 0) {
        stockCheck.push({
          product_id: item.product_id,
          available: false,
          error: 'Produit non trouvé'
        });
        continue;
      }

      const product = products[0];
      stockCheck.push({
        product_id: item.product_id,
        product_name: product.name,
        requested_quantity: quantity,
        current_stock: product.current_stock,
        available: product.current_stock >= quantity,
        unit_price: product.selling_price,
        error: product.current_stock < quantity ? `Stock insuffisant (${product.current_stock} disponible)` : null
      });
    }

    res.json({
      all_available: stockCheck.every(item => item.available),
      stock_check: stockCheck
    });

  } catch (error) {
    console.error('Erreur vérification stock:', error);
    res.status(500).json({ error: 'Erreur lors de la vérification du stock' });
  }
});

app.get('/api/users/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [sellers] = await pool.execute(
      `SELECT id, username, full_name, email, phone, is_active, last_login, created_at
       FROM users
       WHERE company_id = ? AND role = 'seller'
       ORDER BY created_at DESC`,
      [req.user.company_id]
    );
    res.json(sellers);
  } catch (error) {
    console.error('Erreur récupération vendeurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


app.get('/api/reports/sellers-performance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let dateFilter = '';
    const params = [req.user.company_id];
    
    if (start_date && end_date) {
      dateFilter = ' AND s.created_at BETWEEN ? AND ?';
      params.push(start_date + ' 00:00:00', end_date + ' 23:59:59');
    } else {
      // Par défaut, derniers 30 jours
      dateFilter = ' AND s.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    }
    
    const query = `
      SELECT 
        u.id as seller_id,
        u.full_name as seller_name,
        u.username as seller_username,
        COUNT(DISTINCT s.id) as total_sales,
        COALESCE(SUM(s.total_amount), 0) as total_revenue,
        COALESCE(AVG(s.total_amount), 0) as avg_sale_amount,
        COALESCE(SUM(s.total_profit), 0) as total_profit,
        COUNT(DISTINCT DATE(s.created_at)) as active_days,
        MAX(s.created_at) as last_sale_date,
        MIN(s.created_at) as first_sale_date
      FROM users u
      LEFT JOIN sales s ON u.id = s.seller_id ${dateFilter}
      WHERE u.company_id = ? AND u.role = 'seller' AND u.is_active = 1
      GROUP BY u.id, u.full_name, u.username
      ORDER BY total_revenue DESC, total_sales DESC
    `;

    console.log('[DEBUG] Performance query:', query);
    console.log('[DEBUG] Performance params:', params);

    const [performance] = await pool.execute(query, params);
    
    // Ajouter des calculs supplémentaires
    const enrichedPerformance = performance.map(seller => ({
      ...seller,
      avg_daily_sales: seller.active_days > 0 ? (seller.total_sales / seller.active_days).toFixed(1) : 0,
      avg_daily_revenue: seller.active_days > 0 ? (seller.total_revenue / seller.active_days).toFixed(0) : 0,
      has_sales: seller.total_sales > 0
    }));

    console.log('[DEBUG] Performance enriched:', enrichedPerformance);
    res.json(enrichedPerformance);
  } catch (error) {
    console.error('Erreur performance vendeurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/reports/activity-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, action, start_date, end_date } = req.query;

    const pageInt = Math.max(1, parseInt(page) || 1);
    const limitInt = Math.min(1000, Math.max(1, parseInt(limit) || 50));
    const offsetInt = (pageInt - 1) * limitInt;

    let whereConditions = ['al.company_id = ?'];
    const params = [req.user.company_id];

    if (action) {
      whereConditions.push('al.action LIKE ?');
      params.push(`%${action}%`);
    }

    if (start_date) {
      whereConditions.push('DATE(al.created_at) >= ?');
      params.push(start_date);
    }

    if (end_date) {
      whereConditions.push('DATE(al.created_at) <= ?');
      params.push(end_date);
    }

    const query = `
      SELECT 
        al.*,
        u.full_name as user_name,
        u.username as user_username
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE ${whereConditions.join(' AND ')}
      ORDER BY al.created_at DESC 
      LIMIT ${limitInt} OFFSET ${offsetInt}
    `;

    console.log('[DEBUG] Activity logs query:', query);
    console.log('[DEBUG] Activity logs params:', params);

    const [logs] = await pool.execute(query, params);
    
    // Enrichir les logs avec des informations lisibles
    const enrichedLogs = logs.map(log => {
      let details = {};
      try {
        details = JSON.parse(log.details || '{}');
      } catch (e) {
        details = {};
      }

      return {
        ...log,
        details_parsed: details,
        action_readable: getReadableAction(log.action, details),
        time_ago: getTimeAgo(log.created_at)
      };
    });

    res.json(enrichedLogs);
  } catch (error) {
    console.error('Erreur logs d\'activité:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// 4. FONCTION UTILITAIRE POUR RENDRE LES ACTIONS LISIBLES
function getReadableAction(action, details) {
  const actionMap = {
    'successful_login': `Connexion réussie`,
    'failed_login_attempt': `Tentative de connexion échouée`,
    'product_created': `Produit "${details.name || 'N/A'}" créé`,
    'product_updated': `Produit "${details.name || 'N/A'}" modifié`,
    'product_deleted': `Produit "${details.name || 'N/A'}" supprimé`,
    'sale_completed': `Vente ${details.saleNumber || 'N/A'} finalisée (${details.totalAmount || 0} FCFA, ${details.itemCount || 0} articles)`,
    'seller_created': `Vendeur "${details.full_name || details.username || 'N/A'}" créé`,
    'seller_updated': `Vendeur "${details.full_name || 'N/A'}" modifié`,
    'seller_deleted': `Vendeur supprimé`,
    'supplier_created': `Fournisseur "${details.name || 'N/A'}" créé`,
    'supplier_updated': `Fournisseur "${details.name || 'N/A'}" modifié`,
    'supplier_deleted': `Fournisseur supprimé`,
    'expense_created': `Dépense "${details.description || 'N/A'}" créée (${details.amount || 0} FCFA)`,
    'expense_deleted': `Dépense supprimée`,
    'supplier_order_created': `Commande fournisseur "${details.product_name || 'N/A'}" créée (${details.amount || 0} FCFA)`,
    'supplier_order_status_updated': `Statut commande mis à jour : ${details.status || 'N/A'}`,
    'supplier_order_deleted': `Commande fournisseur supprimée`
  };

  return actionMap[action] || `Action: ${action}`;
}

function getTimeAgo(date) {
  const now = new Date();
  const past = new Date(date);
  const diffMs = now - past;
  
  const diffMinutes = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  
  if (diffMinutes < 1) return 'À l\'instant';
  if (diffMinutes < 60) return `Il y a ${diffMinutes} min`;
  if (diffHours < 24) return `Il y a ${diffHours}h`;
  if (diffDays < 7) return `Il y a ${diffDays}j`;
  return past.toLocaleDateString('fr-FR');
}

app.get('/api/reports/company-stats', authenticateToken, async (req, res) => {
  try {
    const { period = '30' } = req.query;

    // CORRECTION: Requêtes différentes selon le rôle
    if (req.user.role === 'admin') {
      // Stats globales pour l'admin
      const [stats] = await pool.execute(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM users WHERE company_id = ? AND role = 'seller' AND is_active = 1) as active_sellers,
          (SELECT COUNT(*) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= COALESCE(min_stock_alert, 5)) as low_stock_products,
          (SELECT COUNT(*) FROM suppliers WHERE company_id = ?) as total_suppliers,
          (SELECT COUNT(*) FROM supplier_orders WHERE company_id = ? AND status = 'pending') as pending_supplier_orders,
          (SELECT COALESCE(SUM(amount), 0) FROM supplier_orders WHERE company_id = ? AND status = 'pending') as pending_supplier_amount,
          (SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE company_id = ? AND expense_date >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_expenses
      `, [
        req.user.company_id, req.user.company_id, req.user.company_id, period,
        req.user.company_id, period, req.user.company_id, period, req.user.company_id,
        req.user.company_id, req.user.company_id, req.user.company_id, req.user.company_id, period
      ]);

      res.json(stats[0]);
    } else {
      // Stats personnelles pour le vendeur
      const [stats] = await pool.execute(`
        SELECT 
          (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
          (SELECT COUNT(*) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
          (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
          (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE seller_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
          (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= COALESCE(min_stock_alert, 5)) as low_stock_products,
          0 as active_sellers,
          0 as total_suppliers,
          0 as pending_supplier_orders,
          0 as pending_supplier_amount,
          0 as recent_expenses
      `, [
        req.user.company_id, 
        req.user.id, period,
        req.user.id, period,
        req.user.id, period,
        req.user.company_id
      ]);

      res.json(stats[0]);
    }

  } catch (error) {
    console.error('Erreur statistiques entreprise:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===============================================
// ROUTES FOURNISSEURS
// ===============================================


app.get('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    console.log('[DEBUG] Suppliers request for company:', req.user.company_id);
    
    const [suppliers] = await pool.execute(
      'SELECT * FROM suppliers WHERE company_id = ? ORDER BY name',
      [req.user.company_id]
    );
    
    console.log('[DEBUG] Suppliers found:', suppliers.length);
    res.json(suppliers);
  } catch (error) {
    console.error('Erreur récupération fournisseurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const { name, contact_person, phone, email, address } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Nom du fournisseur requis' });
    }

    const [result] = await pool.execute(
      `INSERT INTO suppliers (company_id, name, contact_person, phone, email, address) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, name.trim(), contact_person, phone, email, address]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_created', 'supplier', result.insertId, 
      { name: name.trim() }, req.ip);

    res.json({ message: 'Fournisseur créé avec succès', supplierId: result.insertId });
  } catch (error) {
    console.error('Erreur création fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la création du fournisseur' });
  }
});

app.get('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const [suppliers] = await pool.execute(
      `SELECT id, name, contact_person, phone, email, address, is_active, created_at
       FROM suppliers
       WHERE company_id = ?
       ORDER BY name ASC`,
      [req.user.company_id]
    );
    res.json(suppliers);
  } catch (error) {
    console.error('Erreur récupération fournisseurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/suppliers - Créer un fournisseur
app.post('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const { name, contact_person, phone, email, address } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Le nom du fournisseur est obligatoire' });
    }

    // Vérifier si le fournisseur existe déjà
    const [existing] = await pool.execute(
      'SELECT id FROM suppliers WHERE company_id = ? AND LOWER(name) = LOWER(?)',
      [req.user.company_id, name.trim()]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Un fournisseur avec ce nom existe déjà' });
    }

    const [result] = await pool.execute(
      `INSERT INTO suppliers (company_id, name, contact_person, phone, email, address, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        name.trim(),
        contact_person ? contact_person.trim() : null,
        phone ? phone.trim() : null,
        email ? email.trim() : null,
        address ? address.trim() : null,
        req.user.id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_created', 'supplier', result.insertId,
      { name: name.trim() }, req.ip);

    res.json({ 
      message: 'Fournisseur créé avec succès', 
      supplierId: result.insertId 
    });
  } catch (error) {
    console.error('Erreur création fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la création du fournisseur' });
  }
});

// PUT /api/suppliers/:id - Modifier un fournisseur
app.put('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const supplierId = parseInt(req.params.id);
    const { name, contact_person, phone, email, address, is_active } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Le nom du fournisseur est obligatoire' });
    }

    // Vérifier que le fournisseur appartient à l'entreprise
    const [supplier] = await pool.execute(
      'SELECT id, name FROM suppliers WHERE id = ? AND company_id = ?',
      [supplierId, req.user.company_id]
    );

    if (supplier.length === 0) {
      return res.status(404).json({ error: 'Fournisseur non trouvé' });
    }

    // Vérifier unicité du nom (sauf pour le fournisseur actuel)
    const [existing] = await pool.execute(
      'SELECT id FROM suppliers WHERE company_id = ? AND LOWER(name) = LOWER(?) AND id != ?',
      [req.user.company_id, name.trim(), supplierId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Un autre fournisseur avec ce nom existe déjà' });
    }

    await pool.execute(
      `UPDATE suppliers 
       SET name = ?, contact_person = ?, phone = ?, email = ?, address = ?, 
           is_active = COALESCE(?, is_active), updated_at = CURRENT_TIMESTAMP
       WHERE id = ? AND company_id = ?`,
      [
        name.trim(),
        contact_person ? contact_person.trim() : null,
        phone ? phone.trim() : null,
        email ? email.trim() : null,
        address ? address.trim() : null,
        is_active,
        supplierId,
        req.user.company_id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_updated', 'supplier', supplierId,
      { name: name.trim(), previousName: supplier[0].name }, req.ip);

    res.json({ message: 'Fournisseur modifié avec succès' });
  } catch (error) {
    console.error('Erreur modification fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du fournisseur' });
  }
});

// DELETE /api/suppliers/:id - Supprimer un fournisseur
app.delete('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const supplierId = parseInt(req.params.id);

    // Vérifier que le fournisseur appartient à l'entreprise
    const [supplier] = await pool.execute(
      'SELECT id, name FROM suppliers WHERE id = ? AND company_id = ?',
      [supplierId, req.user.company_id]
    );

    if (supplier.length === 0) {
      return res.status(404).json({ error: 'Fournisseur non trouvé' });
    }

    // Vérifier s'il y a des commandes liées
    const [orders] = await pool.execute(
      'SELECT COUNT(*) as count FROM supplier_orders WHERE supplier_id = ?',
      [supplierId]
    );

    if (orders[0].count > 0) {
      return res.status(400).json({ 
        error: 'Impossible de supprimer ce fournisseur car il a des commandes associées' 
      });
    }

    // Vérifier s'il y a des produits liés
    const [products] = await pool.execute(
      'SELECT COUNT(*) as count FROM products WHERE supplier_id = ?',
      [supplierId]
    );

    if (products[0].count > 0) {
      // Mettre à null au lieu de supprimer
      await pool.execute(
        'UPDATE products SET supplier_id = NULL WHERE supplier_id = ?',
        [supplierId]
      );
    }

    await pool.execute(
      'DELETE FROM suppliers WHERE id = ? AND company_id = ?',
      [supplierId, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_deleted', 'supplier', supplierId,
      { name: supplier[0].name }, req.ip);

    res.json({ message: 'Fournisseur supprimé avec succès' });
  } catch (error) {
    console.error('Erreur suppression fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du fournisseur' });
  }
});

// ===== 2. COMMANDES FOURNISSEURS (Supplier Orders) =====

// GET /api/supplier-orders - Liste des commandes/dettes fournisseurs
app.get('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const { status, supplier_id, limit = 50 } = req.query;
    
    let whereClause = 'so.company_id = ?';
    const params = [req.user.company_id];
    
    if (status) {
      whereClause += ' AND so.status = ?';
      params.push(status);
    }
    
    if (supplier_id) {
      whereClause += ' AND so.supplier_id = ?';
      params.push(supplier_id);
    }

    const [orders] = await pool.execute(
      `SELECT so.*, s.name as supplier_name, u.full_name as created_by_name
       FROM supplier_orders so
       LEFT JOIN suppliers s ON so.supplier_id = s.id
       LEFT JOIN users u ON so.created_by = u.id
       WHERE ${whereClause}
       ORDER BY so.created_at DESC
       LIMIT ${parseInt(limit)}`,
      params
    );

    res.json(orders);
  } catch (error) {
    console.error('Erreur récupération commandes fournisseurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/supplier-orders - Créer une commande/dette fournisseur
app.post('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const { supplier_id, product_name, amount, purchase_date, due_date, payment_method } = req.body;

    if (!supplier_id || !product_name || !amount) {
      return res.status(400).json({ 
        error: 'Fournisseur, nom du produit et montant sont obligatoires' 
      });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Montant invalide' });
    }

    // Vérifier que le fournisseur existe et appartient à l'entreprise
    const [supplier] = await pool.execute(
      'SELECT id, name FROM suppliers WHERE id = ? AND company_id = ?',
      [supplier_id, req.user.company_id]
    );

    if (supplier.length === 0) {
      return res.status(400).json({ error: 'Fournisseur non trouvé' });
    }

    const orderNumber = `ORDER-${Date.now()}-${supplier_id}`;
    const status = payment_method === 'credit' ? 'pending' : 'paid';

    const [result] = await pool.execute(
      `INSERT INTO supplier_orders 
       (company_id, supplier_id, order_number, product_name, amount, 
        purchase_date, due_date, payment_method, status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        supplier_id,
        orderNumber,
        product_name.trim(),
        parsedAmount,
        purchase_date,
        due_date,
        payment_method,
        status,
        req.user.id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_created', 'supplier_order', result.insertId,
      { supplierName: supplier[0].name, productName: product_name.trim(), amount: parsedAmount }, req.ip);

    res.json({ 
      message: 'Commande fournisseur créée avec succès', 
      orderId: result.insertId,
      orderNumber
    });
  } catch (error) {
    console.error('Erreur création commande fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la commande' });
  }
});

// PUT /api/supplier-orders/:id - Modifier une commande fournisseur
app.put('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id);
    const { status, payment_date, notes } = req.body;

    // Vérifier que la commande appartient à l'entreprise
    const [order] = await pool.execute(
      `SELECT so.id, so.status, s.name as supplier_name, so.amount
       FROM supplier_orders so
       LEFT JOIN suppliers s ON so.supplier_id = s.id
       WHERE so.id = ? AND so.company_id = ?`,
      [orderId, req.user.company_id]
    );

    if (order.length === 0) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    const updates = [];
    const params = [];
    
    if (status) {
      updates.push('status = ?');
      params.push(status);
    }
    
    if (payment_date) {
      updates.push('payment_date = ?');
      params.push(payment_date);
    }
    
    if (notes !== undefined) {
      updates.push('notes = ?');
      params.push(notes);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Aucune modification spécifiée' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(orderId, req.user.company_id);

    await pool.execute(
      `UPDATE supplier_orders SET ${updates.join(', ')} WHERE id = ? AND company_id = ?`,
      params
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_updated', 'supplier_order', orderId,
      { supplierName: order[0].supplier_name, newStatus: status }, req.ip);

    res.json({ message: 'Commande modifiée avec succès' });
  } catch (error) {
    console.error('Erreur modification commande:', error);
    res.status(500).json({ error: 'Erreur lors de la modification de la commande' });
  }
});

// DELETE /api/supplier-orders/:id - Supprimer une commande fournisseur
app.delete('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id);

    // Vérifier que la commande appartient à l'entreprise
    const [order] = await pool.execute(
      `SELECT so.id, s.name as supplier_name, so.product_name
       FROM supplier_orders so
       LEFT JOIN suppliers s ON so.supplier_id = s.id
       WHERE so.id = ? AND so.company_id = ?`,
      [orderId, req.user.company_id]
    );

    if (order.length === 0) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    await pool.execute(
      'DELETE FROM supplier_orders WHERE id = ? AND company_id = ?',
      [orderId, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_deleted', 'supplier_order', orderId,
      { supplierName: order[0].supplier_name, productName: order[0].product_name }, req.ip);

    res.json({ message: 'Commande supprimée avec succès' });
  } catch (error) {
    console.error('Erreur suppression commande:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression de la commande' });
  }
});

// ===== 3. DÉPENSES (Expenses) =====

// GET /api/expenses - Liste des dépenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { category, start_date, end_date, limit = 100 } = req.query;
    
    let whereClause = 'e.company_id = ?';
    const params = [req.user.company_id];
    
    if (category) {
      whereClause += ' AND e.category = ?';
      params.push(category);
    }
    
    if (start_date) {
      whereClause += ' AND DATE(e.expense_date) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      whereClause += ' AND DATE(e.expense_date) <= ?';
      params.push(end_date);
    }

    const [expenses] = await pool.execute(
      `SELECT e.*, u.full_name as created_by_name
       FROM expenses e
       LEFT JOIN users u ON e.created_by = u.id
       WHERE ${whereClause}
       ORDER BY e.expense_date DESC, e.created_at DESC
       LIMIT ${parseInt(limit)}`,
      params
    );

    res.json(expenses);
  } catch (error) {
    console.error('Erreur récupération dépenses:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/expenses - Créer une dépense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, category, expense_date } = req.body;

    if (!description || description.trim().length === 0) {
      return res.status(400).json({ error: 'La description est obligatoire' });
    }

    if (!amount) {
      return res.status(400).json({ error: 'Le montant est obligatoire' });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Montant invalide' });
    }

    const expenseDate = expense_date || new Date().toISOString().split('T')[0];
    const expenseCategory = category && category.trim().length > 0 ? category.trim() : 'Autre';

    const [result] = await pool.execute(
      `INSERT INTO expenses (company_id, description, amount, category, expense_date, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        description.trim(),
        parsedAmount,
        expenseCategory,
        expenseDate,
        req.user.id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'expense_created', 'expense', result.insertId,
      { description: description.trim(), amount: parsedAmount, category: expenseCategory }, req.ip);

    res.json({ 
      message: 'Dépense créée avec succès', 
      expenseId: result.insertId 
    });
  } catch (error) {
    console.error('Erreur création dépense:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la dépense' });
  }
});

// DELETE /api/expenses/:id - Supprimer une dépense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const expenseId = parseInt(req.params.id);

    // Vérifier que la dépense appartient à l'entreprise
    const [expense] = await pool.execute(
      'SELECT id, description, amount FROM expenses WHERE id = ? AND company_id = ?',
      [expenseId, req.user.company_id]
    );

    if (expense.length === 0) {
      return res.status(404).json({ error: 'Dépense non trouvée' });
    }

    await pool.execute(
      'DELETE FROM expenses WHERE id = ? AND company_id = ?',
      [expenseId, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'expense_deleted', 'expense', expenseId,
      { description: expense[0].description, amount: expense[0].amount }, req.ip);

    res.json({ message: 'Dépense supprimée avec succès' });
  } catch (error) {
    console.error('Erreur suppression dépense:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression de la dépense' });
  }
});

// ===== 4. GESTION VENDEURS - POST/PUT/DELETE =====

// POST /api/users/sellers - Créer un vendeur (Admin uniquement)
app.post('/api/users/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, full_name, email, phone } = req.body;

    if (!username || !password || !full_name) {
      return res.status(400).json({ 
        error: 'Nom d\'utilisateur, mot de passe et nom complet sont obligatoires' 
      });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Le nom d\'utilisateur doit contenir au moins 3 caractères' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    // Vérifier unicité du nom d'utilisateur
    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE username = ?',
      [username.trim()]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.execute(
      `INSERT INTO users (company_id, username, password, full_name, email, phone, role, created_by)
       VALUES (?, ?, ?, ?, ?, ?, 'seller', ?)`,
      [
        req.user.company_id,
        username.trim(),
        hashedPassword,
        full_name.trim(),
        email ? email.trim() : null,
        phone ? phone.trim() : null,
        req.user.id
      ]
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_created', 'user', result.insertId,
      { username: username.trim(), fullName: full_name.trim() }, req.ip);

    res.json({ 
      message: 'Vendeur créé avec succès', 
      sellerId: result.insertId 
    });
  } catch (error) {
    console.error('Erreur création vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la création du vendeur' });
  }
});

// PUT /api/users/sellers/:id - Modifier un vendeur (Admin uniquement)
app.put('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const sellerId = parseInt(req.params.id);
    const { full_name, email, phone, is_active, password } = req.body;

    // Vérifier que le vendeur existe et appartient à l'entreprise
    const [seller] = await pool.execute(
      'SELECT id, username, full_name FROM users WHERE id = ? AND company_id = ? AND role = ?',
      [sellerId, req.user.company_id, 'seller']
    );

    if (seller.length === 0) {
      return res.status(404).json({ error: 'Vendeur non trouvé' });
    }

    const updates = [];
    const params = [];

    if (full_name && full_name.trim().length > 0) {
      updates.push('full_name = ?');
      params.push(full_name.trim());
    }

    if (email !== undefined) {
      updates.push('email = ?');
      params.push(email ? email.trim() : null);
    }

    if (phone !== undefined) {
      updates.push('phone = ?');
      params.push(phone ? phone.trim() : null);
    }

    if (is_active !== undefined) {
      updates.push('is_active = ?');
      params.push(is_active);
    }

    if (password && password.length >= 6) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push('password = ?');
      params.push(hashedPassword);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Aucune modification spécifiée' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(sellerId, req.user.company_id);

    await pool.execute(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ? AND company_id = ?`,
      params
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_updated', 'user', sellerId,
      { username: seller[0].username, previousName: seller[0].full_name }, req.ip);

    res.json({ message: 'Vendeur modifié avec succès' });
  } catch (error) {
    console.error('Erreur modification vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du vendeur' });
  }
});

// DELETE /api/users/sellers/:id - Supprimer un vendeur (Admin uniquement)
app.delete('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const sellerId = parseInt(req.params.id);

    // Vérifier que le vendeur existe et appartient à l'entreprise
    const [seller] = await pool.execute(
      'SELECT id, username, full_name FROM users WHERE id = ? AND company_id = ? AND role = ?',
      [sellerId, req.user.company_id, 'seller']
    );

    if (seller.length === 0) {
      return res.status(404).json({ error: 'Vendeur non trouvé' });
    }

    // Vérifier s'il y a des ventes associées
    const [sales] = await pool.execute(
      'SELECT COUNT(*) as count FROM sales WHERE seller_id = ?',
      [sellerId]
    );

    if (sales[0].count > 0) {
      // Désactiver au lieu de supprimer si il y a des ventes
      await pool.execute(
        'UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [sellerId]
      );

      await logActivity(req.user.company_id, req.user.id, 'seller_deactivated', 'user', sellerId,
        { username: seller[0].username, reason: 'has_sales' }, req.ip);

      return res.json({ 
        message: 'Vendeur désactivé (il avait des ventes associées)', 
        action: 'deactivated' 
      });
    }

    // Supprimer complètement si pas de ventes
    await pool.execute(
      'DELETE FROM users WHERE id = ? AND company_id = ?',
      [sellerId, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'seller_deleted', 'user', sellerId,
      { username: seller[0].username, fullName: seller[0].full_name }, req.ip);

    res.json({ message: 'Vendeur supprimé avec succès' });
  } catch (error) {
    console.error('Erreur suppression vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du vendeur' });
  }
});

// Middleware de gestion d'erreurs
app.use((error, req, res, next) => {
  console.error('Erreur non gérée:', error);
  res.status(500).json({ error: 'Erreur serveur interne' });
});

// Route 404
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

// Démarrage du serveur
const startServer = async () => {
  try {
    await testConnection();



    app.listen(port, () => {
      console.log(`🚀 Serveur démarré sur le port ${port}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
    });
  } catch (error) {
    console.error('❌ Erreur de démarrage:', error);
    process.exit(1);
  }
};

// Gestion propre de l'arrêt
process.on('SIGINT', async () => {
  console.log('\n🔄 Arrêt du serveur...');
  await pool.end();
  console.log('✅ Connexions fermées');
  process.exit(0);
});

startServer();
