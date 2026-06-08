-- Fix account 'dummy' dengan password 'test123'
-- MD5('test123') = cc03e747a6afbbcbf8be7668acfebee5

UPDATE accounts
SET password_hash = 'cc03e747a6afbbcbf8be7668acfebee5'
WHERE username = 'dummy';

-- Atau delete dan re-register
-- DELETE FROM accounts WHERE username = 'dummy';
