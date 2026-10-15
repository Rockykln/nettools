-- IEEE MAC address block assignments (MA-L /24, MA-M /28, MA-S /36). Filled by `npm run mac:update` + `npm run db:seed`.
CREATE TABLE mac_vendors (
  prefix TEXT PRIMARY KEY,   -- upper-case hex, 6, 7 or 9 digits
  bits INTEGER NOT NULL,     -- 24, 28 or 36
  vendor TEXT NOT NULL,
  country TEXT
);
