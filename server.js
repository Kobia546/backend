const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Middlewares de sécurité
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));



app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Configuration MySQL
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'inventory_system',

};

const pool = mysql.createPool(dbConfig);

// Test de connexion à la base de données
const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connexion MySQL établie avec succès');
    connection.release();
  } catch (error) {
    console.error('❌ Erreur de connexion MySQL:', error.message);
    process.exit(1);
  }
};

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
    // Si on n'a pas de company_id, ne pas logger (tentatives de connexion échouées)
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
    console.error('Erreur création vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la création du vendeur' });
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

// Gestion des produits
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, description, barcode, category, supplier_id, purchase_price, selling_price, initial_stock } = req.body;

    if (!name || !purchase_price || !selling_price) {
      return res.status(400).json({ error: 'Champs obligatoires manquants' });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
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

      const [result] = await connection.execute(
        `INSERT INTO products (company_id, name, description, barcode, category, supplier_id, 
         purchase_price, selling_price, current_stock, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.company_id, name, description, barcode, category, supplier_id, 
         purchase_price, selling_price, initial_stock || 0, req.user.id]
      );

      const productId = result.insertId;

      // Mouvement de stock initial
      if (initial_stock > 0) {
        await connection.execute(
          `INSERT INTO stock_movements (company_id, product_id, movement_type, quantity, 
           unit_cost, reference_type, user_id) 
           VALUES (?, ?, 'in', ?, ?, 'manual', ?)`,
          [req.user.company_id, productId, initial_stock, purchase_price, req.user.id]
        );
      }

      await logActivity(req.user.company_id, req.user.id, 'product_created', 'product', productId, 
        { name, initial_stock }, req.ip);

      await connection.commit();
      res.json({ message: 'Produit créé avec succès', productId });

    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }

  } catch (error) {
    console.error('Erreur création produit:', error);
    if (error.message.includes('code-barres')) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Erreur lors de la création du produit' });
    }
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
    console.error('Erreur récupération produits:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route de vente
app.post('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { items, customer_name, customer_phone, payment_method, discount = 0 } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Aucun article dans la vente' });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
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
          throw new Error(`Stock insuffisant pour le produit ${item.product_id}`);
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
        [req.user.company_id, saleNumber, customer_name, customer_phone, 
         subtotal, discount, totalAmount, totalProfit, payment_method, req.user.id]
      );

      const saleId = saleResult.insertId;

      // Ajouter les items (les triggers MySQL géreront les stocks automatiquement)
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
          [saleId, item.product_id, product.name, item.quantity,
           product.selling_price, product.purchase_price, lineTotal, lineProfit]
        );
      }

      await logActivity(req.user.company_id, req.user.id, 'sale_completed', 'sale', saleId,
        { saleNumber, totalAmount, itemCount: items.length }, req.ip);

      await connection.commit();
      res.json({ 
        message: 'Vente enregistrée avec succès', 
        saleId, 
        saleNumber,
        totalAmount, 
        totalProfit 
      });

    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }

  } catch (error) {
    console.error('Erreur création vente:', error);
    res.status(500).json({ error: error.message });
  }
});

// Routes pour les rapports admin
app.get('/api/reports/company-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { period = '30' } = req.query;

    const [stats] = await pool.execute(`
      SELECT 
        (SELECT COUNT(*) FROM products WHERE company_id = ?) as total_products,
        (SELECT COUNT(*) FROM users WHERE company_id = ? AND role = 'seller' AND is_active = 1) as active_sellers,
        (SELECT COUNT(*) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_sales,
        (SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_revenue,
        (SELECT COALESCE(SUM(total_profit), 0) FROM sales WHERE company_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)) as recent_profit,
        (SELECT COUNT(*) FROM products WHERE company_id = ? AND current_stock <= min_stock_alert) as low_stock_products
    `, [
      req.user.company_id, req.user.company_id, req.user.company_id, period,
      req.user.company_id, period, req.user.company_id, period, req.user.company_id
    ]);

    res.json(stats[0]);

  } catch (error) {
    console.error('Erreur statistiques entreprise:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/api/suppliers', authenticateToken, async (req, res) => {
  try {
    const [suppliers] = await pool.execute(
      'SELECT * FROM suppliers WHERE company_id = ? ORDER BY name',
      [req.user.company_id]
    );
    res.json(suppliers);
  } catch (error) {
    console.error('Erreur récupération fournisseurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Créer un fournisseur
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
    console.error('Erreur création fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la création du fournisseur' });
  }
});

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
    console.error('Erreur modification fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du fournisseur' });
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
    console.error('Erreur suppression fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du fournisseur' });
  }
});

// ===============================================
// ROUTES SUPPLIER ORDERS (COMMANDES/DETTES FOURNISSEURS) - COMPLÈTES
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
    console.error('Erreur récupération commandes fournisseurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
    console.error('Erreur création commande fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la commande fournisseur' });
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
    console.error('Erreur modification statut commande:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du statut' });
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
    console.error('Erreur suppression commande fournisseur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression de la commande' });
  }
});

// ===============================================
// ROUTES EXPENSES (DÉPENSES) - COMPLÈTES
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
    console.error('Erreur récupération dépenses:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
    console.error('Erreur création dépense:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la dépense' });
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
    console.error('Erreur suppression dépense:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression de la dépense' });
  }
});

// ===============================================
// ROUTES PRODUITS MANQUANTES (UPDATE, DELETE)
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
    console.error('Erreur modification produit:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du produit' });
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
    console.error('Erreur suppression produit:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du produit' });
  }
});

// ===============================================
// ROUTES VENTES (GET) - MANQUANTE
// ===============================================

// Récupérer les ventes
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { limit = 10, page = 1, start_date, end_date } = req.query;
    
    let query = `
      SELECT s.*, u.full_name as seller_name,
             COUNT(si.id) as items_count
      FROM sales s
      LEFT JOIN users u ON s.seller_id = u.id
      LEFT JOIN sale_items si ON s.id = si.sale_id
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
    
    query += ` GROUP BY s.id
               ORDER BY s.created_at DESC 
               LIMIT ? OFFSET ?`;
    
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const [sales] = await pool.execute(query, params);
    
    // Récupérer les détails des articles pour chaque vente
    for (let sale of sales) {
      const [items] = await pool.execute(
        'SELECT * FROM sale_items WHERE sale_id = ?',
        [sale.id]
      );
      sale.items = items;
    }

    res.json(sales);
  } catch (error) {
    console.error('Erreur récupération ventes:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===============================================
// ROUTES VENDEURS MANQUANTES (UPDATE, DELETE)
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
    console.error('Erreur modification vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du vendeur' });
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
    console.error('Erreur suppression vendeur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du vendeur' });
  }
});

// ===============================================
// ROUTES ADMIN MANQUANTES
// ===============================================

// Performance des vendeurs
app.get('/api/reports/sellers-performance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let query = `
      SELECT 
        u.id as seller_id,
        u.full_name as seller_name,
        COUNT(s.id) as total_sales,
        COALESCE(SUM(s.total_amount), 0) as total_revenue,
        COALESCE(AVG(s.total_amount), 0) as avg_sale_amount,
        COALESCE(SUM(s.total_profit), 0) as total_profit
      FROM users u
      LEFT JOIN sales s ON u.id = s.seller_id
    `;
    
    const params = [req.user.company_id];
    
    if (start_date && end_date) {
      query += ' AND s.created_at BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }
    
    query += ` WHERE u.company_id = ? AND u.role = 'seller'
               GROUP BY u.id, u.full_name
               ORDER BY total_revenue DESC`;

    const [performance] = await pool.execute(query, params);
    res.json(performance);
  } catch (error) {
    console.error('Erreur performance vendeurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
    console.error('Erreur logs d\'activité:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Statistiques étendues
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
    console.error('Erreur statistiques entreprise:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
    async function testDatabaseConnection() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
      connectTimeout: 10000, // 10 secondes
    });
    await connection.connect();
    console.log("✅ Connexion à Railway réussie depuis Render !");
    await connection.end();
  } catch (error) {
    console.error("❌ Échec de la connexion à Railway :", error.message);
    if (error.code === 'ETIMEDOUT') {
      console.error("Le serveur Render ne parvient pas à joindre Railway. Vérifiez le proxy ou le pare-feu.");
    }
  }
}

testDatabaseConnection();
    
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