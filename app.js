```javascript
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const Sequelize = require('sequelize');
const PDFDocument = require('pdfkit');
const Papa = require('papaparse');
const winston = require('winston');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 8000;

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.File({ filename: 'audit.log' })]
});

// Sequelize setup
const sequelize = new Sequelize(process.env.DATABASE_URL, { dialect: 'postgres' });
const User = sequelize.define('User', {
  username: { type: Sequelize.STRING, unique: true, allowNull: false },
  password: { type: Sequelize.STRING, allowNull: false }
});
const Facility = sequelize.define('Facility', { name: { type: Sequelize.STRING, allowNull: false } });
const Commodity = sequelize.define('Commodity', { name: { type: Sequelize.STRING, allowNull: false } });
const Report = sequelize.define('Report', {
  userId: { type: Sequelize.INTEGER, allowNull: false },
  facilityId: { type: Sequelize.INTEGER, allowNull: false },
  reportDate: { type: Sequelize.DATEONLY, allowNull: false }
});
const ReportItem = sequelize.define('ReportItem', {
  reportId: { type: Sequelize.INTEGER, allowNull: false },
  commodityId: { type: Sequelize.INTEGER, allowNull: false },
  quantity: { type: Sequelize.INTEGER, allowNull: false }
});
const AuditLog = sequelize.define('AuditLog', {
  userId: { type: Sequelize.INTEGER, allowNull: false },
  action: { type: Sequelize.STRING, allowNull: false },
  timestamp: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.NOW }
});

// Associations
Report.belongsTo(User);
Report.belongsTo(Facility);
ReportItem.belongsTo(Report);
ReportItem.belongsTo(Commodity);
AuditLog.belongsTo(User);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('static'));
app.set('view engine', 'ejs');
app.set('views', 'templates');
app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false
}));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Initialize database
async function initDb() {
  await sequelize.sync();
  const admin = await User.findOne({ where: { username: 'admin' } });
  if (!admin) {
    await User.create({ username: 'admin', password: process.env.ADMIN_PASSWORD || 'default_password' });
    await Facility.bulkCreate([{ name: 'Facility A' }, { name: 'Facility B' }]);
    await Commodity.bulkCreate([{ name: 'Item X' }, { name: 'Item Y' }]);
  }
}
initDb();

// Routes
app.get(['/', '/login'], (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });
  if (user && user.password === password) {
    req.session.userId = user.id;
    await AuditLog.create({ userId: user.id, action: 'Logged in' });
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('dashboard');
});

app.get('/submit-report', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('submit_report');
});

app.post('/submit-report', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const { facilityId, commodityId, quantity, reportDate } = req.body;
  const report = await Report.create({ userId: req.session.userId, facilityId, reportDate });
  await ReportItem.create({ reportId: report.id, commodityId, quantity });
  await AuditLog.create({ userId: req.session.userId, action: `Submitted report for facility ${facilityId}` });
  res.redirect('/dashboard');
});

app.get('/view-reports', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const reports = await Report.findAll();
  const reportItems = await ReportItem.findAll({ include: [Report, Commodity] });
  const facilities = await Facility.findAll();
  const commodities = await Commodity.findAll();
  res.render('view_reports', { reports, reportItems, facilities, commodities });
});

app.get('/export-reports', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const reportItems = await ReportItem.findAll({ include: [Report, Commodity, { model: Report, include: [Facility] }] });
  const doc = new PDFDocument();
  const buffers = [];
  doc.on('data', buffers.push.bind(buffers));
  doc.on('end', () => {
    const pdfData = Buffer.concat(buffers);
    res.setHeader('Content-Disposition', 'attachment; filename=reports.pdf');
    res.setHeader('Content-Type', 'application/pdf');
    res.send(pdfData);
  });
  doc.text('Inventory Reports', 100, 50);
  let y = 100;
  reportItems.forEach(item => {
    const facilityName = item.Report.Facility.name;
    const commodityName = item.Commodity.name;
    doc.text(`Report ${item.reportId}: ${facilityName} - ${commodityName} - ${item.quantity} - ${item.Report.reportDate}`, 100, y);
    y += 20;
  });
  doc.end();
});

app.get('/import-reports', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('import_reports');
});

app.post('/import-reports', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const file = req.body.file; // Requires multer for file uploads; simplify for demo
  Papa.parse(file, {
    header: true,
    complete: async (result) => {
      for (const row of result.data) {
        const report = await Report.create({ userId: req.session.userId, facilityId: row.facilityId, reportDate: row.reportDate });
        await ReportItem.create({ reportId: report.id, commodityId: row.commodityId, quantity: row.quantity });
      }
      res.redirect('/dashboard');
    }
  });
});

app.get('/analytics', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('analytics');
});

app.get('/api/reports', async (req, res) => {
  const reportItems = await ReportItem.findAll({ include: [Report, Commodity, { model: Report, include: [Facility] }] });
  res.json(reportItems.map(r => ({
    id: r.id,
    reportId: r.reportId,
    facilityId: r.Report.facilityId,
    commodityId: r.commodityId,
    quantity: r.quantity,
    reportDate: r.Report.reportDate
  })));
});

app.get('/api/facilities', async (req, res) => {
  const facilities = await Facility.findAll();
  res.json(facilities.map(f => ({ id: f.id, name: f.name })));
});

app.get('/api/commodities', async (req, res) => {
  const commodities = await Commodity.findAll();
  res.json(commodities.map(c => ({ id: c.id, name: c.name })));
});

app.post('/api/sync-reports', async (req, res) => {
  const { facilityId, commodityId, quantity, reportDate } = req.body;
  const report = await Report.create({ userId: 1, facilityId, reportDate });
  await ReportItem.create({ reportId: report.id, commodityId, quantity });
  res.json({ status: 'success' });
});

app.listen(port, () => {
  logger.info(`Server running on port ${port}`);
});
```
