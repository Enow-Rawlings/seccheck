import os
import json
from datetime import datetime

# Check if running on Railway (has DATABASE_URL)
DATABASE_URL = os.environ.get('DATABASE_URL')
print(f"DEBUG: DATABASE_URL exists: {bool(DATABASE_URL)}")
print(f"DEBUG: DATABASE_URL value: {DATABASE_URL[:50] if DATABASE_URL else 'None'}")

if DATABASE_URL:
    # Use PostgreSQL on Railway
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    def get_connection():
        return psycopg2.connect(DATABASE_URL, sslmode='require')
    
    def init_db():
        """Initialize PostgreSQL database"""
        conn = get_connection()
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL,
                score INTEGER,
                grade TEXT,
                scan_date TIMESTAMP,
                results TEXT,
                user_ip TEXT
            )
        ''')
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_date ON scans(scan_date DESC)')
        
        conn.commit()
        conn.close()
        print("✓ PostgreSQL database initialized")
    
    def save_scan(domain, results, user_ip=None):
        """Save scan to PostgreSQL"""
        conn = get_connection()
        c = conn.cursor()
        
        score_data = results.get('score', {})
        score_value = score_data.get('score', 0)
        
        if 'grade' not in score_data:
            if score_value >= 90: grade = 'A'
            elif score_value >= 80: grade = 'B'
            elif score_value >= 70: grade = 'C'
            elif score_value >= 60: grade = 'D'
            else: grade = 'F'
        else:
            grade = score_data['grade']
        
        c.execute('''
            INSERT INTO scans (domain, score, grade, scan_date, results, user_ip)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (domain, score_value, grade, datetime.now(), json.dumps(results), user_ip))
        
        scan_id = c.fetchone()[0]
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_scan_by_id(scan_id):
        """Get scan by ID from PostgreSQL"""
        conn = get_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        c.execute('''
            SELECT id, domain, score, grade, scan_date, results, user_ip
            FROM scans
            WHERE id = %s
        ''', (scan_id,))
        
        row = c.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def get_scan_history(domain, limit=10):
        """Get scan history for domain from PostgreSQL"""
        conn = get_connection()
        c = conn.cursor()
        
        c.execute('''
            SELECT id, score, grade, scan_date
            FROM scans
            WHERE domain = %s
            ORDER BY scan_date DESC
            LIMIT %s
        ''', (domain, limit))
        
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'score': row[1],
                'grade': row[2],
                'date': str(row[3])
            })
        
        return history
    
    def get_all_scans_grouped(limit=50):
        """Get all scans grouped by domain from PostgreSQL"""
        conn = get_connection()
        c = conn.cursor()
        
        c.execute('''
            SELECT s1.domain, 
                   COUNT(*) as scan_count, 
                   MAX(s1.scan_date) as last_scan,
                   (SELECT score FROM scans s2 WHERE s2.domain = s1.domain ORDER BY scan_date DESC LIMIT 1) as latest_score,
                   AVG(s1.score) as avg_score,
                   MIN(s1.score) as min_score, 
                   MAX(s1.score) as max_score
            FROM scans s1
            GROUP BY s1.domain
            ORDER BY last_scan DESC
            LIMIT %s
        ''', (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        domains = []
        for row in rows:
            domains.append({
                'domain': row[0],
                'scan_count': row[1],
                'last_scan': str(row[2]),
                'latest_score': row[3] if row[3] else 0,
                'avg_score': round(row[4], 1) if row[4] else 0,
                'min_score': row[5],
                'max_score': row[6]
            })
        
        return domains

else:
    # Use SQLite locally
    import sqlite3
    
    def init_db():
        """Initialize SQLite database"""
        conn = sqlite3.connect('seccheck.db')
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                score INTEGER,
                grade TEXT,
                scan_date TIMESTAMP,
                results TEXT,
                user_ip TEXT
            )
        ''')
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_date ON scans(scan_date DESC)')
        
        conn.commit()
        conn.close()
        print("✓ SQLite database initialized")
    
    def save_scan(domain, results, user_ip=None):
        """Save scan to SQLite"""
        conn = sqlite3.connect('seccheck.db')
        c = conn.cursor()
        
        score_data = results.get('score', {})
        score_value = score_data.get('score', 0)
        
        if 'grade' not in score_data:
            if score_value >= 90: grade = 'A'
            elif score_value >= 80: grade = 'B'
            elif score_value >= 70: grade = 'C'
            elif score_value >= 60: grade = 'D'
            else: grade = 'F'
        else:
            grade = score_data['grade']
        
        c.execute('''
            INSERT INTO scans (domain, score, grade, scan_date, results, user_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (domain, score_value, grade, datetime.now(), json.dumps(results), user_ip))
        
        conn.commit()
        scan_id = c.lastrowid
        conn.close()
        
        return scan_id
    
    def get_scan_by_id(scan_id):
        """Get scan by ID from SQLite"""
        conn = sqlite3.connect('seccheck.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''
            SELECT id, domain, score, grade, scan_date, results, user_ip
            FROM scans
            WHERE id = ?
        ''', (scan_id,))
        
        row = c.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def get_scan_history(domain, limit=10):
        """Get scan history for domain from SQLite"""
        conn = sqlite3.connect('seccheck.db')
        c = conn.cursor()
        
        c.execute('''
            SELECT id, score, grade, scan_date
            FROM scans
            WHERE domain = ?
            ORDER BY scan_date DESC
            LIMIT ?
        ''', (domain, limit))
        
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'score': row[1],
                'grade': row[2],
                'date': row[3]
            })
        
        return history
    
    def get_all_scans_grouped(limit=50):
        """Get all scans grouped by domain from SQLite"""
        conn = sqlite3.connect('seccheck.db')
        c = conn.cursor()
        
        c.execute('''
            SELECT s1.domain, 
                   COUNT(*) as scan_count, 
                   MAX(s1.scan_date) as last_scan,
                   (SELECT score FROM scans s2 WHERE s2.domain = s1.domain ORDER BY scan_date DESC LIMIT 1) as latest_score,
                   AVG(s1.score) as avg_score,
                   MIN(s1.score) as min_score, 
                   MAX(s1.score) as max_score
            FROM scans s1
            GROUP BY s1.domain
            ORDER BY last_scan DESC
            LIMIT ?
        ''', (limit,))
        
        rows = c.fetchall()
        conn.close()
        
        domains = []
        for row in rows:
            domains.append({
                'domain': row[0],
                'scan_count': row[1],
                'last_scan': row[2],
                'latest_score': row[3] if row[3] else 0,
                'avg_score': round(row[4], 1) if row[4] else 0,
                'min_score': row[5],
                'max_score': row[6]
            })
        
        return domains
