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

// Middleware pour gérer les erreurs JSON
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

// Configuration MySQL avec gestion des reconnexions
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5571,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  idleTimeout: 300000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

async function testConnection() {
  try {
    const conn = await pool.getConnection();
    console.log('✅ Connecté à Nodechef !');
    conn.release();
  } catch (err) {
    console.error('❌ Erreur MySQL :', err.message);
  }
}

testConnection();

// Middleware d'authentification avec gestion d'erreurs améliorée
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
    console.error('Erreur authentification:', error);
    if (error.code === 'ECONNRESET' || error.code === 'ER_SERVER_SHUTDOWN') {
      return res.status(503).json({ error: 'Service temporairement indisponible' });
    }
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

// Fonction de logging d'activité avec gestion d'erreurs

// Update your server.js with these corrected routes:

// 1. Fixed sales query (replace around line 537)
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { limit = 10, page = 1, start_date, end_date } = req.query;
    
    // Use subquery to avoid GROUP BY issues
    let query = `
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
    
    if (start_date) {
      query += ' AND DATE(s.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      query += ' AND DATE(s.created_at) <= ?';
      params.push(end_date);
    }
    
    query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [sales] = await pool.execute(query, params);
    
    // Get sale items for each sale
    for (let sale of sales) {
      const [items] = await pool.execute(
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

// 2. Improved error handling for logActivity function (replace around line 120)
const logActivity = async (companyId, userId, action, entityType = null, entityId = null, details = {}, ipAddress = null) => {
  try {
    if (!companyId) {
      console.log(`[LOG] ${action} - ${JSON.stringify(details)} - IP: ${ipAddress}`);
      return;
    }

    // Ensure companyId is never null for database insert
    if (!companyId || companyId === null) {
      console.warn('Skipping activity log - no company_id provided');
      return;
    }

    await pool.execute(
      `INSERT INTO activity_logs (company_id, user_id, action, entity_type, entity_id, details, ip_address) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [companyId, userId, action, entityType, entityId, JSON.stringify(details), ipAddress]
    );
  } catch (error) {
    console.error('Erreur log activité:', error);
    // Don't fail the main request if logging fails
  }
};

// Fonction utilitaire pour gérer les erreurs de base de données
const handleDatabaseError = (error, res, customMessage = 'Erreur serveur') => {
  console.error('Erreur base de données:', error);
  
  if (error.code === 'ECONNRESET' || error.code === 'ER_SERVER_SHUTDOWN') {
    return res.status(503).json({ error: 'Service de base de données temporairement indisponible. Veuillez réessayer.' });
  }
  
  if (error.code === 'ER_NO_DEFAULT_FOR_FIELD') {
    return res.status(500).json({ error: 'Erreur de configuration de base de données. Veuillez contacter l\'administrateur.' });
  }
  
  if (error.code === 'ER_DUP_ENTRY') {
    return res.status(400).json({ error: 'Cette entrée existe déjà dans la base de données.' });
  }
  
  return res.status(500).json({ error: customMessage });
};

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
    handleDatabaseError(error, res, 'Erreur de connexion');
  }
});

// Gestion des utilisateurs (vendeurs)
app.post('/api/users/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, full_name, email, phone } = req.body;

    if (!username || !password || !full_name) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
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
    const [sellers] = await pool.execute(
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

// Gestion des produits
// Replace your product creation route with this corrected version:

app.post('/api/products', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, initial_stock } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    await connection.beginTransaction();

    // Vérifier unicité du code-barres dans l'entreprise si fourni
    if (barcode) {
      const [existing] = await connection.execute(
        'SELECT id FROM products WHERE company_id = ? AND barcode = ?',
        [req.user.company_id, barcode]
      );
      if (existing.length > 0) {
        throw new Error('Ce code-barres existe déjà dans votre entreprise');
      }
    }

    // Make sure all numeric values are properly handled
    const purchasePrice = parseFloat(purchase_price);
    const sellingPrice = parseFloat(selling_price);
    const stockValue = parseInt(initial_stock) || 0;
    const supplierIdValue = supplier_id ? parseInt(supplier_id) : null;

    // Insert product - let MySQL handle the AUTO_INCREMENT id
    const [result] = await connection.execute(
      `INSERT INTO products (company_id, name, description, barcode, category, supplier_id, 
       purchase_price, selling_price, current_stock, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id, 
        name, 
        description || null, 
        barcode || null, 
        category || 'Non catégorisé', 
        supplierIdValue, 
        purchasePrice, 
        sellingPrice, 
        stockValue, 
        req.user.id
      ]
    );

    const productId = result.insertId;

    // Mouvement de stock initial
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
      { name, initial_stock: stockValue }, req.ip);

    res.json({ message: 'Produit créé avec succès', productId });

  } catch (error) {
    await connection.rollback();
    
    // More specific error handling
    console.error('Product creation error:', error);
    
    if (error.message.includes('code-barres')) {
      res.status(400).json({ error: error.message });
    } else if (error.code === 'ER_NO_DEFAULT_FOR_FIELD') {
      res.status(500).json({ error: 'Erreur de configuration de base de données. Champ manquant requis.' });
    } else if (error.code === 'ER_BAD_NULL_ERROR') {
      res.status(400).json({ error: 'Valeur requise manquante pour un champ obligatoire.' });
    } else {
      handleDatabaseError(error, res, 'Erreur lors de la création du produit');
    }
  } finally {
    connection.release();
  }
});

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { search, category, low_stock, page = 1, limit = 50 } = req.query;
    
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

    if (category) {
      query += ' AND p.category = ?';
      params.push(category);
    }

    if (low_stock === 'true') {
      query += ' AND p.current_stock <= p.min_stock_alert';
    }

    query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [products] = await pool.execute(query, params);
    res.json(products);

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des produits');
  }
});

// Route de vente
app.post('/api/sales', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { items, customer_name, customer_phone, payment_method, discount = 0 } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Aucun article dans la vente' });
    }

    await connection.beginTransaction();

    let subtotal = 0;
    let totalProfit = 0;
    const saleNumber = `SALE-${Date.now()}-${req.user.id}`;

    // Vérifier stock et calculer totaux
    for (const item of items) {
      const [products] = await connection.execute(
        'SELECT current_stock, purchase_price, selling_price FROM products WHERE id = ? AND company_id = ?',
        [item.product_id, req.user.company_id]
      );

      if (products.length === 0) {
        throw new Error(`Produit ${item.product_id} non trouvé`);
      }

      const product = products[0];

      if (product.current_stock < item.quantity) {
        throw new Error(`Stock insuffisant pour le produit ${item.product_id} (stock actuel: ${product.current_stock}, demandé: ${item.quantity})`);
      }

      const lineTotal = product.selling_price * item.quantity;
      const lineProfit = (product.selling_price - product.purchase_price) * item.quantity;

      subtotal += lineTotal;
      totalProfit += lineProfit;
    }

    const totalAmount = subtotal - discount;

    // Créer la vente
    const [saleResult] = await connection.execute(
      `INSERT INTO sales (company_id, sale_number, customer_name, customer_phone,
       subtotal, discount, total_amount, total_profit, payment_method, seller_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.company_id,
        saleNumber,
        customer_name,
        customer_phone,
        subtotal,
        discount,
        totalAmount,
        totalProfit,
        payment_method,
        req.user.id
      ]
    );

    const saleId = saleResult.insertId;

    // Ajouter les items et mettre à jour le stock
    for (const item of items) {
      const [products] = await connection.execute(
        'SELECT name, purchase_price, selling_price FROM products WHERE id = ?',
        [item.product_id]
      );

      const product = products[0];
      const lineTotal = product.selling_price * item.quantity;
      const lineProfit = (product.selling_price - product.purchase_price) * item.quantity;

      // Insérer l'article de vente
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

      // Mettre à jour le stock du produit
      await connection.execute(
        `UPDATE products
         SET current_stock = current_stock - ?
         WHERE id = ? AND company_id = ?`,
        [item.quantity, item.product_id, req.user.company_id]
      );

      // Ajouter un mouvement de stock (sortie)
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

    // Log de l'activité
    await logActivity(
      req.user.company_id,
      req.user.id,
      'sale_completed',
      'sale',
      saleId,
      { saleNumber, totalAmount, itemCount: items.length },
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

    // Gestion d'erreur personnalisée
    if (error.message.includes('Stock insuffisant')) {
      return res.status(400).json({ error: error.message });
    } else if (error.message.includes('non trouvé')) {
      return res.status(404).json({ error: error.message });
    } else {
      handleDatabaseError(error, res, 'Erreur lors de l\'enregistrement de la vente');
    }

  } finally {
    connection.release();
  }
});

// Routes pour les fournisseurs
app.get('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const [suppliers] = await pool.execute(
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

    const [result] = await pool.execute(
      `INSERT INTO suppliers (company_id, name, contact_person, phone, email, address) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, name, contact_person, phone, email, address]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_created', 'supplier', result.insertId, 
      { name }, req.ip);

    res.json({ message: 'Fournisseur créé avec succès', supplierId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création du fournisseur');
  }
});

// Récupérer les ventes
// Better approach: Use subquery or ANY_VALUE() function
// Replace the problematic sales query with this more robust version:
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { limit = 10, page = 1, start_date, end_date } = req.query;
    
    // Use subquery to avoid GROUP BY issues
    let query = `
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
    
    if (start_date) {
      query += ' AND DATE(s.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      query += ' AND DATE(s.created_at) <= ?';
      params.push(end_date);
    }
    
    query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [sales] = await pool.execute(query, params);
    
    // Get sale items for each sale
    for (let sale of sales) {
      const [items] = await pool.execute(
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
// ===============================================
// ROUTES SUPPLIER ORDERS (COMMANDES/DETTES FOURNISSEURS)
// ===============================================

// Récupérer toutes les commandes fournisseurs
app.get('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.execute(
      `SELECT so.*, s.name as supplier_name 
       FROM supplier_orders so
       JOIN suppliers s ON so.supplier_id = s.id
       WHERE so.company_id = ? 
       ORDER BY so.due_date ASC, so.created_at DESC`,
      [req.user.company_id]
    );
    res.json(orders);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des commandes fournisseurs');
  }
});

// Créer une commande fournisseur
app.post('/api/supplier-orders', authenticateToken, async (req, res) => {
  try {
    const { supplier_id, product_name, amount, purchase_date, due_date, payment_method } = req.body;
    
    if (!supplier_id || !product_name || !amount) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const [result] = await pool.execute(
      `INSERT INTO supplier_orders (company_id, supplier_id, product_name, amount, purchase_date, due_date, payment_method) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.user.company_id, supplier_id, product_name, amount, purchase_date, due_date, payment_method]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_created', 'supplier_order', result.insertId, 
      { product_name, amount }, req.ip);

    res.json({ message: 'Commande fournisseur créée avec succès', orderId: result.insertId });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la création de la commande fournisseur');
  }
});

// Modifier le statut d'une commande fournisseur
app.put('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    await pool.execute(
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

// Supprimer une commande fournisseur
app.delete('/api/supplier-orders/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.execute(
      'DELETE FROM supplier_orders WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'supplier_order_deleted', 'supplier_order', id, 
      {}, req.ip);

    res.json({ message: 'Commande fournisseur supprimée avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression de la commande');
  }
});

// ===============================================
// ROUTES EXPENSES (DÉPENSES)
// ===============================================

// Récupérer toutes les dépenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const [expenses] = await pool.execute(
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

// Créer une dépense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, category, expense_date } = req.body;
    
    if (!description || !amount) {
      return res.status(400).json({ error: 'Description et montant requis' });
    }

    const [result] = await pool.execute(
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

// Modifier une dépense
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { description, amount, category, expense_date } = req.body;

    await pool.execute(
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

// Supprimer une dépense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.execute(
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
// ROUTES PRODUITS - OPERATIONS MANQUANTES
// ===============================================

// Modifier un produit
app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, current_stock } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    // Vérifier que le produit appartient à l'entreprise
    const [existing] = await pool.execute(
      'SELECT id FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    await pool.execute(
      `UPDATE products SET name = ?, description = ?, barcode = ?, category = ?, 
       supplier_id = ?, purchase_price = ?, selling_price = ?, current_stock = ?, updated_at = NOW()
       WHERE id = ? AND company_id = ?`,
      [name, description, barcode, category, supplier_id, purchase_price, selling_price, current_stock, id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'product_updated', 'product', id, 
      { name }, req.ip);

    res.json({ message: 'Produit modifié avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la modification du produit');
  }
});

// Supprimer un produit
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Vérifier que le produit appartient à l'entreprise et n'a pas de ventes
    const [product] = await pool.execute(
      `SELECT p.name, COUNT(si.id) as sale_count 
       FROM products p 
       LEFT JOIN sale_items si ON p.id = si.product_id 
       WHERE p.id = ? AND p.company_id = ?
       GROUP BY p.id, p.name`,
      [id, req.user.company_id]
    );

    if (product.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    if (product[0].sale_count > 0) {
      return res.status(400).json({ error: 'Impossible de supprimer un produit ayant des ventes associées' });
    }

    await pool.execute(
      'DELETE FROM products WHERE id = ? AND company_id = ?',
      [id, req.user.company_id]
    );

    await logActivity(req.user.company_id, req.user.id, 'product_deleted', 'product', id, 
      { name: product[0].name }, req.ip);

    res.json({ message: 'Produit supprimé avec succès' });
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la suppression du produit');
  }
});

// ===============================================
// ROUTES FOURNISSEURS - OPERATIONS MANQUANTES
// ===============================================

// Modifier un fournisseur
app.put('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, contact_person, phone, email, address } = req.body;

    await pool.execute(
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

// Supprimer un fournisseur
app.delete('/api/suppliers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.execute(
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
// ROUTES VENDEURS - OPERATIONS MANQUANTES
// ===============================================

// Modifier un vendeur
app.put('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, email, phone, is_active } = req.body;

    await pool.execute(
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

// Supprimer un vendeur
app.delete('/api/users/sellers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Vérifier que le vendeur n'a pas de ventes
    const [sales] = await pool.execute(
      'SELECT COUNT(*) as sale_count FROM sales WHERE seller_id = ?',
      [id]
    );

    if (sales[0].sale_count > 0) {
      return res.status(400).json({ error: 'Impossible de supprimer un vendeur ayant des ventes associées' });
    }

    await pool.execute(
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
// ROUTES ADMIN - RAPPORTS AVANCES
// ===============================================

// Performance des vendeurs
// Replace the sellers performance query (around line 810) with this optimized version:

app.get('/api/reports/sellers-performance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let query = `
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
      query += ' AND s.created_at BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }
    
    query += `
        GROUP BY seller_id
      ) sales_stats ON u.id = sales_stats.seller_id
      WHERE u.company_id = ? AND u.role = 'seller'
      ORDER BY total_revenue DESC
    `;

    const [performance] = await pool.execute(query, params);
    res.json(performance);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des performances vendeurs');
  }
});

// Logs d'activité
app.get('/api/reports/activity-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, action, start_date, end_date } = req.query;
    
    let query = `
      SELECT al.*, u.full_name as user_name
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.company_id = ?
    `;
    
    const params = [req.user.company_id];
    
    if (action) {
      query += ' AND al.action LIKE ?';
      params.push(`%${action}%`);
    }
    
    if (start_date) {
      query += ' AND DATE(al.created_at) >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      query += ' AND DATE(al.created_at) <= ?';
      params.push(end_date);
    }
    
    query += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [logs] = await pool.execute(query, params);
    res.json(logs);
  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des logs d\'activité');
  }
});

// Routes pour les rapports admin
app.get('/api/reports/company-stats', authenticateToken, async (req, res) => {
  try {
    const { period = '30' } = req.query;

    const [stats] = await pool.execute(`
      SELECT 
        (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
        (SELECT COUNT(*) FROM users WHERE company_id = ? AND role = 'seller' AND is_active = 1) as active_sellers,
        (SELECT COUNT(*) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
        (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
        (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
        (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= min_stock_alert) as low_stock_products,
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

  } catch (error) {
    handleDatabaseError(error, res, 'Erreur lors de la récupération des statistiques');
  }
});

// Middleware de gestion d'erreurs global
app.use((error, req, res, next) => {
  console.error('Erreur non gérée:', error);
  
  // Erreur de parsing JSON
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ 
      error: 'Données JSON invalides dans la requête' 
    });
  }
  
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
  try {
    await pool.end();
    console.log('✅ Connexions fermées');
  } catch (error) {
    console.error('Erreur lors de la fermeture:', error);
  }
  process.exit(0);
});

startServer();