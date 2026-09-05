# Factory Control Plane

الأداة الداخلية التي ينشئ بها فريقكم مواقع حملات جديدة لجهات إعلامية جديدة، ويديرون بها الجهات
القائمة. تعمل كخدمة Node دائمة على Render، بقاعدة بيانات Render واحدة مشتركة بينها وبين كل
الجهات (كل جهة في مخطط Postgres خاص بها).

للتعليمات الكاملة من الصفر حتى أول جهة منشورة، راجع **`../DEPLOYMENT_GUIDE.md`**. هذا الملف
مرجع سريع لبنية هذا المجلد تحديدًا.

## بنية الكود

```
server.js               نقطة دخول Render — خادم Node، يخدم dashboard.html ويوجّه /api/factory/*
dashboard.html           واجهة لوحة التحكم (عربية بالكامل)
api/[...path].js         كل مسارات الـ API: مصادقة + تحقق بخطوتين، إدارة الجهات، سجل التدقيق
lib/
  db.js                  باني استعلامات Postgres (نفس النمط المستخدم في قالب الجهة)
  db.test.js             اختبارات db.js
  tenantDb.js             إنشاء/حذف/تعديل مخطط كل جهة على الخادم المشترك
  provisioning.js         خط أنابيب إنشاء جهة جديدة (10 خطوات)
  vercelClient.js          عميل Vercel API — نشر موقع الجهة
  secretsVault.js          تشفير AES-256-GCM لمفاتيح Vercel
  totp.js                  مصادقة ثنائية (RFC 6238)، بلا اعتماديات خارجية
  passwordUtils.js          تجزئة كلمات المرور (PBKDF2)
migrations/001_factory_schema.sql   مخطط قاعدة بيانات المصنع نفسها
tenant-migrations/                   نسخة من migrations/ الخاصة بقالب الجهة، تُستخدم أثناء إنشاء أي جهة
render.yaml                          Render Blueprint — خدمة واحدة + قاعدة بيانات واحدة
```

## أهم مسارات الـ API

| المسار | الوصف |
|---|---|
| `POST /api/factory/bootstrap` | إنشاء أول مشرف عام (مرة واحدة فقط) |
| `POST /api/factory/auth/login` → `/auth/totp/verify` | تسجيل الدخول + التحقق بخطوتين |
| `GET`/`POST /api/factory/tenants` | قائمة الجهات / إنشاء جهة جديدة |
| `GET /api/factory/jobs/:id` | متابعة تقدّم إنشاء جهة |
| `POST /api/factory/tenants/:id/suspend`\|`resume`\|`delete` | إدارة دورة حياة الجهة |
| `GET`/`POST /api/factory/tenants/:id/site-settings` | عرض/تعديل الهوية البصرية (شعار، ألوان، منصات) |
| `GET /api/factory/tenants/:id/admin-password` | عرض كلمة مرور الأدمن لمرة واحدة |
| `GET /api/factory/audit-log` | سجل تدقيق كل الإجراءات |

## ملاحظات أمنية

- لوحة التحكم/الـ API ليست مفتوحة CORS عمدًا — نفس المصدر فقط.
- امنح دور التطبيق صلاحيات INSERT/SELECT فقط على `factory_activity_logs` (أبدًا UPDATE/DELETE)
  حتى يبقى سجل التدقيق غير قابل للتلاعب.
- `FACTORY_ENCRYPTION_KEY` هو نقطة الفشل الوحيدة لتشفير الأسرار — عامله كمفتاح جذر، وأعد توليده
  إن تعرّض للانكشاف.
- كل الجهات تتشارك حد `max_connections` في Postgres — راقب هذا مع نمو عدد الجهات.
