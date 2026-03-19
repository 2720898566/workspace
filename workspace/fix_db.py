import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'db.sqlite3')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 检查表结构
cursor.execute('PRAGMA table_info(scanner_scheduledtask)')
columns = cursor.fetchall()
print('Current columns:')
for col in columns:
    print(f'  {col[1]}: {col[2]}')

# 添加缺失的列
try:
    cursor.execute('ALTER TABLE scanner_scheduledtask ADD COLUMN day_of_week VARCHAR(20)')
    print('Added day_of_week column')
except Exception as e:
    print(f'Error: {e}')

conn.commit()
conn.close()
print('Done!')
