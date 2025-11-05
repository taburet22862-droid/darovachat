from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'super-secret-darova-2024-key-change-me'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7
CORS(app)

DATABASE = 'darova_chat.db'


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT,
            avatar TEXT,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id)
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(friend_id) REFERENCES users(id)
        )''')

        # Добавь после создания других таблиц в init_db()
        cursor.execute('''CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS server_members (
            id INTEGER PRIMARY KEY,
            server_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member', -- owner, admin, member
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(server_id) REFERENCES servers(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            UNIQUE(server_id, user_id)
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS server_messages (
            id INTEGER PRIMARY KEY,
            server_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(server_id) REFERENCES servers(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        )''')

        # Создаём админа только если его нет
        cursor.execute('SELECT * FROM users WHERE username = ?', ('darovaadmin',))
        if not cursor.fetchone():
            hashed = generate_password_hash('posnos123')
            cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                           ('darovaadmin', hashed, 1))
            print("👤 нет")

        # Создаём тестового пользователя только если его нет
        cursor.execute('SELECT * FROM users WHERE username = ?', ('testuser',))
        if not cursor.fetchone():
            hashed = generate_password_hash('test123')
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                           ('testuser', hashed))
            print("👥 Тестовый пользователь создан: testuser / test123")

        db.commit()
        db.close()
        print("✅ База данных инициализирована")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        print(f"[LOGIN] Username: {username}, Password: {password}")

        if not username or not password:
            return jsonify({'success': False, 'error': 'Заполни все поля'}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        db.close()

        print(f"[LOGIN] User found: {user is not None}")

        if not user:
            print(f"[LOGIN] User not found")
            return jsonify({'success': False, 'error': 'Пользователь не найден'}), 401

        if user['is_banned']:
            print(f"[LOGIN] User is banned")
            return jsonify({'success': False, 'error': f'Ты забанен! Причина: {user["ban_reason"]}'}), 403

        # Проверяем пароль
        print(f"[LOGIN] Checking password. Hash in DB: {user['password'][:20]}...")
        password_match = check_password_hash(user['password'], password)
        print(f"[LOGIN] Password match result: {password_match}")

        if password_match:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            print(f"[LOGIN] Session set successfully. Session: {dict(session)}")
            return jsonify({'success': True, 'is_admin': user['is_admin']})
        else:
            print(f"[LOGIN] Password mismatch")
            return jsonify({'success': False, 'error': 'Неверный пароль'}), 401
    except Exception as e:
        print(f"[LOGIN] Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Юзернейм минимум 3 символа'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Пароль минимум 6 символов'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        hashed = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
        db.commit()

        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        db.close()

        session['user_id'] = user['id']
        session['username'] = username
        session['is_admin'] = 0

        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'success': False, 'error': 'Юзернейм уже занят'}), 400
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/user')
def get_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, username, display_name, avatar, is_admin FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    db.close()

    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'display_name': user['display_name'] or user['username'],
        'avatar': user['avatar'],
        'is_admin': user['is_admin']
    })


@app.route('/api/friends')
def get_friends():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    db = get_db()
    cursor = db.cursor()

    # ИСПРАВЛЕННЫЙ ЗАПРОС - убираем дублирование
    cursor.execute('''SELECT DISTINCT u.id, u.username, u.display_name, u.avatar, u.is_banned 
                      FROM users u
                      JOIN friends f ON u.id = f.friend_id
                      WHERE f.user_id = ? AND f.status = 'accepted'
                      ORDER BY u.username''',
                   (session['user_id'],))

    friends = cursor.fetchall()
    db.close()

    return jsonify([dict(f) for f in friends])


@app.route('/api/add-friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    username = data.get('username', '').strip()

    db = get_db()
    cursor = db.cursor()

    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    friend = cursor.fetchone()

    if not friend:
        db.close()
        return jsonify({'success': False, 'error': 'Пользователь не найден'}), 404

    if friend['id'] == session['user_id']:
        db.close()
        return jsonify({'success': False, 'error': 'Нельзя добавить себя'}), 400

    cursor.execute('''SELECT * FROM friends WHERE 
                      (user_id = ? AND friend_id = ?) OR 
                      (user_id = ? AND friend_id = ?)''',
                   (session['user_id'], friend['id'], friend['id'], session['user_id']))

    if cursor.fetchone():
        db.close()
        return jsonify({'success': False, 'error': 'Уже в друзьях или заявка отправлена'}), 400

    cursor.execute('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)',
                   (session['user_id'], friend['id'], 'accepted'))
    cursor.execute('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)',
                   (friend['id'], session['user_id'], 'accepted'))
    db.commit()
    db.close()

    return jsonify({'success': True})


@app.route('/api/messages/<int:friend_id>')
def get_messages(friend_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM direct_messages 
                      WHERE (sender_id = ? AND recipient_id = ?) OR 
                            (sender_id = ? AND recipient_id = ?)
                      ORDER BY created_at ASC''',
                   (session['user_id'], friend_id, friend_id, session['user_id']))
    messages = cursor.fetchall()
    db.close()

    return jsonify([dict(m) for m in messages])


@app.route('/api/send-message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    recipient_id = data.get('recipient_id')
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'success': False, 'error': 'Сообщение пусто'}), 400

    # Проверяем, не забанен ли отправитель
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT is_banned FROM users WHERE id = ?', (session['user_id'],))
    sender = cursor.fetchone()

    if sender['is_banned']:
        db.close()
        return jsonify({'success': False, 'error': 'Ты забанен и не можешь отправлять сообщения'}), 403

    cursor.execute('INSERT INTO direct_messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
                   (session['user_id'], recipient_id, message))
    db.commit()

    cursor.execute('SELECT * FROM direct_messages WHERE id = last_insert_rowid()')
    msg = cursor.fetchone()
    db.close()

    return jsonify({
        'success': True,
        'message': dict(msg)
    })


@app.route('/api/search-users', methods=['GET'])
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    query = request.args.get('q', '').strip()

    if len(query) < 1:
        return jsonify([])

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'SELECT id, username, display_name, avatar, is_banned FROM users WHERE (username LIKE ? OR display_name LIKE ?) AND id != ? LIMIT 10',
        (f'%{query}%', f'%{query}%', session['user_id']))
    users = cursor.fetchall()
    db.close()

    return jsonify([dict(u) for u in users])


# ===== АДМИН ПАНЕЛЬ =====

@app.route('/api/admin/users')
def admin_get_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, username, display_name, is_admin, is_banned, ban_reason, created_at FROM users')
    users = cursor.fetchall()
    db.close()

    return jsonify([dict(u) for u in users])


@app.route('/api/admin/ban-user', methods=['POST'])
def admin_ban_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json()
    user_id = data.get('user_id')
    reason = data.get('reason', 'Нарушение правил')

    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Ты не можешь забанить себя'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ?',
                   (reason, user_id))
    db.commit()
    db.close()

    return jsonify({'success': True, 'message': 'Пользователь забанен'})


@app.route('/api/admin/unban-user', methods=['POST'])
def admin_unban_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE id = ?', (user_id,))
    db.commit()
    db.close()

    return jsonify({'success': True, 'message': 'Пользователь разбанен'})


@app.route('/api/admin/make-admin', methods=['POST'])
def admin_make_admin():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
    db.commit()
    db.close()

    return jsonify({'success': True, 'message': 'Пользователь стал администратором'})


@app.route('/api/admin/remove-admin', methods=['POST'])
def admin_remove_admin():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Ты не можешь забрать админку у себя'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET is_admin = 0 WHERE id = ?', (user_id,))
    db.commit()
    db.close()

    return jsonify({'success': True, 'message': 'Админка отобрана'})


@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    display_name = data.get('display_name', '').strip()
    avatar = data.get('avatar', '').strip()

    if not display_name:
        display_name = None

    if len(display_name or '') > 50:
        return jsonify({'success': False, 'error': 'Отображаемое имя не должно превышать 50 символов'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET display_name = ?, avatar = ? WHERE id = ?',
                   (display_name, avatar, session['user_id']))
    db.commit()
    db.close()

    return jsonify({'success': True, 'message': 'Профиль обновлен'})


# ===== СЕРВЕРЫ =====

@app.route('/api/servers/create', methods=['POST'])
def create_server():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()

    if not name:
        return jsonify({'success': False, 'error': 'Название сервера обязательно'}), 400

    if len(name) > 50:
        return jsonify({'success': False, 'error': 'Название сервера не более 50 символов'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Создаем сервер
        cursor.execute('INSERT INTO servers (name, description, owner_id) VALUES (?, ?, ?)',
                       (name, description, session['user_id']))
        server_id = cursor.lastrowid

        # Добавляем создателя как владельца
        cursor.execute('INSERT INTO server_members (server_id, user_id, role) VALUES (?, ?, ?)',
                       (server_id, session['user_id'], 'owner'))

        db.commit()
        db.close()

        return jsonify({'success': True, 'server_id': server_id})
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/servers')
def get_servers():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    db = get_db()
    cursor = db.cursor()

    # Получаем серверы где пользователь является участником
    cursor.execute('''SELECT s.*, sm.role 
                      FROM servers s
                      JOIN server_members sm ON s.id = sm.server_id
                      WHERE sm.user_id = ?
                      ORDER BY s.name''', (session['user_id'],))

    servers = cursor.fetchall()
    db.close()

    return jsonify([dict(server) for server in servers])


@app.route('/api/servers/<int:server_id>/join', methods=['POST'])
def join_server(server_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    db = get_db()
    cursor = db.cursor()

    try:
        # Проверяем существует ли сервер
        cursor.execute('SELECT * FROM servers WHERE id = ?', (server_id,))
        server = cursor.fetchone()
        if not server:
            db.close()
            return jsonify({'success': False, 'error': 'Сервер не найден'}), 404

        # Проверяем уже ли участник
        cursor.execute('SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
                       (server_id, session['user_id']))
        if cursor.fetchone():
            db.close()
            return jsonify({'success': False, 'error': 'Уже участник сервера'}), 400

        # Добавляем как участника
        cursor.execute('INSERT INTO server_members (server_id, user_id, role) VALUES (?, ?, ?)',
                       (server_id, session['user_id'], 'member'))

        db.commit()
        db.close()

        return jsonify({'success': True})
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/servers/<int:server_id>/messages')
def get_server_messages(server_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Проверяем что пользователь участник сервера
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
                   (server_id, session['user_id']))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'Not a member'}), 403

    cursor.execute('''SELECT sm.*, u.username, u.display_name, u.avatar 
                      FROM server_messages sm
                      JOIN users u ON sm.sender_id = u.id
                      WHERE sm.server_id = ?
                      ORDER BY sm.created_at ASC''', (server_id,))

    messages = cursor.fetchall()
    db.close()

    return jsonify([dict(msg) for msg in messages])


@app.route('/api/servers/send-message', methods=['POST'])
def send_server_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    server_id = data.get('server_id')
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'success': False, 'error': 'Сообщение пусто'}), 400

    # Проверяем что пользователь участник сервера
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
                   (server_id, session['user_id']))
    if not cursor.fetchone():
        db.close()
        return jsonify({'success': False, 'error': 'Not a member'}), 403

    # Проверяем бан
    cursor.execute('SELECT is_banned FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    if user['is_banned']:
        db.close()
        return jsonify({'success': False, 'error': 'Ты забанен'}), 403

    cursor.execute('INSERT INTO server_messages (server_id, sender_id, message) VALUES (?, ?, ?)',
                   (server_id, session['user_id'], message))
    db.commit()

    cursor.execute('''SELECT sm.*, u.username, u.display_name, u.avatar 
                      FROM server_messages sm
                      JOIN users u ON sm.sender_id = u.id
                      WHERE sm.id = last_insert_rowid()''')
    msg = cursor.fetchone()
    db.close()

    return jsonify({
        'success': True,
        'message': dict(msg)
    })


@app.route('/api/servers/<int:server_id>/members')
def get_server_members(server_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Проверяем что пользователь участник сервера
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
                   (server_id, session['user_id']))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'Not a member'}), 403

    cursor.execute('''SELECT u.id, u.username, u.display_name, u.avatar, u.is_banned, sm.role
                      FROM server_members sm
                      JOIN users u ON sm.user_id = u.id
                      WHERE sm.server_id = ?
                      ORDER BY 
                        CASE sm.role 
                            WHEN 'owner' THEN 1
                            WHEN 'admin' THEN 2
                            ELSE 3 
                        END, u.username''', (server_id,))

    members = cursor.fetchall()
    db.close()

    return jsonify([dict(member) for member in members])

if __name__ == '__main__':
    # Всегда инициализируем БД (создаем таблицы если их нет)
    init_db()

    print("🚀 DarovaChat запущен на http://localhost:5000")
    app.run(debug=True, port=5000)