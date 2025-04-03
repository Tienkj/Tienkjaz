from flask import Flask, request, send_from_directory, send_file, render_template_string, url_for, redirect, session, abort, jsonify
import os
import re
import unicodedata
import json
from io import BytesIO
import zipfile
import requests
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong secret key
UPLOAD_FOLDER = "uploads"
PASSWORD_FILE = "passwords.json"
ACCESS_LOG_FILE = "access_log.json"
ADMIN_PASSWORD = "Tien6kjaz"  # Admin password
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Load passwords from JSON file if exists
if os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        file_passwords = json.load(f)
else:
    file_passwords = {}

def save_passwords():
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump(file_passwords, f, ensure_ascii=False, indent=2)

def custom_secure_filename(filename):
    """Keep Unicode characters while removing special chars"""
    filename = os.path.basename(filename)
    filename = unicodedata.normalize('NFKC', filename)
    filename = re.sub(r'[^\w\s.-]', '', filename, flags=re.UNICODE)
    filename = filename.replace(' ', '_')
    return filename

def get_folder_list():
    """Get list of subfolders in UPLOAD_FOLDER"""
    folders = []
    for item in os.listdir(UPLOAD_FOLDER):
        if os.path.isdir(os.path.join(UPLOAD_FOLDER, item)):
            folders.append(item)
    return folders

def get_files_grouped():
    """Group files by folder with viewable status"""
    allowed_image_extensions = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
    allowed_video_extensions = {"mp4", "avi", "mov", "wmv", "flv", "webm", "mkv"}
    allowed_text_extensions = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "json", "xml", "html", "htm", "js", "css", "py"}
    grouped = {"root": []}
    
    # Files in root
    for item in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, item)
        if os.path.isfile(path):
            ext = item.rsplit('.', 1)[-1].lower() if '.' in item else ''
            grouped["root"].append({
                "name": item,
                "viewable": ext in allowed_image_extensions or ext in allowed_video_extensions,
                "text": ext in allowed_text_extensions
            })
    
    # Files in subfolders
    for folder in get_folder_list():
        folder_path = os.path.join(UPLOAD_FOLDER, folder)
        grouped[folder] = []
        for f in os.listdir(folder_path):
            full_path = os.path.join(folder_path, f)
            if os.path.isfile(full_path):
                ext = f.rsplit('.', 1)[-1].lower() if '.' in f else ''
                grouped[folder].append({
                    "name": f,
                    "viewable": ext in allowed_image_extensions or ext in allowed_video_extensions,
                    "text": ext in allowed_text_extensions
                })
    return grouped

def log_access(ip, user_agent, action, is_admin=False, filename=None):
    """Log access with geo information"""
    try:
        # Get geo info from IPAPI
        geo_info = {}
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,query")
            geo_info = response.json()
        except Exception as e:
            geo_info = {"error": str(e)}
        
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "user_agent": user_agent,
            "action": action,
            "is_admin": is_admin,
            "filename": filename,
            "geo_info": geo_info
        }
        
        # Read existing logs
        logs = []
        if os.path.exists(ACCESS_LOG_FILE):
            with open(ACCESS_LOG_FILE, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        
        # Add new log
        logs.append(log_entry)
        
        # Save logs (keep only last 1000 entries)
        with open(ACCESS_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs[-1000:], f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"Error logging access: {str(e)}")

def detect_device(user_agent):
    """Simple device detection from user agent"""
    ua = user_agent.lower()
    if 'iphone' in ua or 'ipad' in ua or 'ipod' in ua:
        return 'iOS'
    elif 'android' in ua:
        return 'Android'
    elif 'windows' in ua:
        return 'Windows'
    elif 'mac os' in ua:
        return 'Mac'
    elif 'linux' in ua:
        return 'Linux'
    return 'Unknown'

def detect_browser(user_agent):
    """Simple browser detection from user agent"""
    ua = user_agent.lower()
    if 'chrome' in ua:
        return 'Chrome'
    elif 'firefox' in ua:
        return 'Firefox'
    elif 'safari' in ua:
        return 'Safari'
    elif 'edge' in ua:
        return 'Edge'
    elif 'opera' in ua:
        return 'Opera'
    elif 'msie' in ua or 'trident' in ua:
        return 'IE'
    return 'Unknown'

def format_file_size(size):
    """Convert file size to human readable format"""
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024*1024:
        return f"{size/1024:.1f} KB"
    elif size < 1024*1024*1024:
        return f"{size/(1024*1024):.1f} MB"
    else:
        return f"{size/(1024*1024*1024):.1f} GB"

# --------------------- ROUTES ---------------------

@app.route("/delete_file", methods=["POST"])
def delete_file():
    """Delete a specific file (admin only)"""
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    data = request.get_json()
    folder = data.get("folder", "root")
    filename = data.get("filename")
    
    if not filename:
        return jsonify({"success": False, "message": "Filename is required"}), 400
    
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], folder, filename) if folder != "root" else os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    if not os.path.exists(filepath):
        return jsonify({"success": False, "message": "File not found"}), 404
    
    try:
        os.remove(filepath)
        # Remove password if exists
        key = f"{folder}/{filename}" if folder != "root" else filename
        if key in file_passwords:
            del file_passwords[key]
            save_passwords()
        
        log_access(request.remote_addr, request.user_agent.string, f"Xóa file {filename}", True, filename)
        return jsonify({"success": True, "message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error deleting file: {str(e)}"}), 500

@app.route("/")
def index():
    """Main page with file listing"""
    folders = get_folder_list()
    files = get_files_grouped()
    log_access(request.remote_addr, request.user_agent.string, "Truy cập trang chủ")
    return render_template_string(INDEX_TEMPLATE, folders=folders, files=files, admin_logged_in=session.get("admin_logged_in", False))

@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    """Admin panel with access logs and statistics"""
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            log_access(request.remote_addr, request.user_agent.string, "Đăng nhập admin thành công", True)
            return redirect(url_for('admin_panel'))
        else:
            log_access(request.remote_addr, request.user_agent.string, "Đăng nhập admin thất bại")
            return "Sai mật khẩu admin", 403
    
    if not session.get("admin_logged_in"):
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Đăng nhập Admin</title>
            <style>
                body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .login-box { background: rgba(0,0,0,0.5); padding: 30px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.3); text-align: center; max-width: 400px; width: 90%; }
                h2 { margin-top: 0; color: #ffd700; }
                input[type="password"] { width: 100%; padding: 12px; margin: 15px 0; border: none; border-radius: 8px; background: rgba(255,255,255,0.1); color: white; }
                button { background: linear-gradient(45deg, #ff7eb3, #ff527b); color: white; border: none; padding: 12px 25px; border-radius: 8px; cursor: pointer; font-weight: bold; width: 100%; transition: all 0.3s; }
                button:hover { transform: translateY(-3px); box-shadow: 0 4px 8px rgba(0,0,0,0.3); }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Đăng nhập Admin</h2>
                <form method="post">
                    <input type="password" name="password" placeholder="Nhập mật khẩu admin" required>
                    <button type="submit">Đăng nhập</button>
                </form>
            </div>
        </body>
        </html>
        '''
    
    # Load logs with pagination and search
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    logs_per_page = 20
    
    all_logs = []
    if os.path.exists(ACCESS_LOG_FILE):
        with open(ACCESS_LOG_FILE, "r", encoding="utf-8") as f:
            try:
                all_logs = json.load(f)
            except:
                all_logs = []
    
    # Filter logs if search query exists
    if search_query:
        search_query = search_query.lower()
        filtered_logs = []
        for log in all_logs:
            if (search_query in log.get('ip', '').lower() or 
                search_query in log.get('action', '').lower() or 
                search_query in log.get('user_agent', '').lower() or
                (log.get('filename') and search_query in log['filename'].lower())):
                filtered_logs.append(log)
        all_logs = filtered_logs
    
    # Reverse to show newest first
    all_logs = list(reversed(all_logs))
    
    # Calculate statistics
    total_visits = len(all_logs)
    today_visits = 0
    admin_visits = 0
    upload_count = 0
    today = datetime.now().strftime("%Y-%m-%d")
    
    for log in all_logs:
        if log.get('timestamp', '').startswith(today):
            today_visits += 1
        if log.get('is_admin', False):
            admin_visits += 1
        if 'upload' in log.get('action', '').lower():
            upload_count += 1
    
    # Pagination
    total_logs = len(all_logs)
    pages = (total_logs // logs_per_page) + (1 if total_logs % logs_per_page else 0)
    start_idx = (page - 1) * logs_per_page
    end_idx = start_idx + logs_per_page
    logs = all_logs[start_idx:end_idx]
    
    return render_template_string(
        ADMIN_TEMPLATE,
        logs=logs,
        page=page,
        pages=pages,
        search_query=search_query,
        total_visits=total_visits,
        today_visits=today_visits,
        admin_visits=admin_visits,
        upload_count=upload_count,
        detect_device=detect_device,
        detect_browser=detect_browser
    )

@app.route("/admin/logout")
def admin_logout():
    """Logout from admin panel"""
    log_access(request.remote_addr, request.user_agent.string, "Đăng xuất admin", True)
    session.pop("admin_logged_in", None)
    return redirect(url_for('index'))

@app.route("/admin/clear_logs")
def clear_logs():
    """Clear all access logs (admin only)"""
    if not session.get("admin_logged_in"):
        return redirect(url_for('admin_panel'))
    
    with open(ACCESS_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("[]")
    
    log_access(request.remote_addr, request.user_agent.string, "Xóa tất cả logs", True)
    return redirect(url_for('admin_panel'))

@app.route("/delete_all_files")
def delete_all_files():
    """Delete all files (admin only)"""
    if not session.get("admin_logged_in"):
        return redirect(url_for('admin_panel'))
    
    # Delete all files and folders
    for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER'], topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    
    # Clear passwords
    global file_passwords
    file_passwords = {}
    save_passwords()
    
    log_access(request.remote_addr, request.user_agent.string, "Xóa tất cả file", True)
    return redirect(url_for('admin_panel'))

@app.route("/view_logs")
def view_logs():
    """View logs - only accessible by admin"""
    if not session.get("admin_logged_in"):
        return redirect(url_for('admin_panel'))
    
    logs = []
    if os.path.exists(ACCESS_LOG_FILE):
        with open(ACCESS_LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    
    # Only show basic info and limit to 50 entries
    simple_logs = []
    for log in reversed(logs[-50:]):
        simple_logs.append({
            "time": log.get("timestamp"),
            "action": log.get("action"),
            "ip": log.get("ip"),
            "location": f"{log.get('geo_info', {}).get('city', '')}, {log.get('geo_info', {}).get('regionName', '')}",
            "device": detect_device(log.get('user_agent', '')),
            "browser": detect_browser(log.get('user_agent', ''))
        })
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Lịch sử truy cập</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; margin-bottom: 30px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f8f8f8; font-weight: bold; position: sticky; top: 0; }
            tr:hover { background-color: #f5f5f5; }
            .back-btn { display: inline-block; margin-top: 20px; padding: 10px 15px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }
            .admin-log { background-color: #fff0f0; }
            .device-icon { font-size: 14px; margin-right: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Lịch sử truy cập gần đây</h1>
            <table>
                <thead>
                    <tr>
                        <th>Thời gian</th>
                        <th>Hành động</th>
                        <th>IP</th>
                        <th>Vị trí</th>
                        <th>Thiết bị</th>
                        <th>Trình duyệt</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr class="{% if 'admin' in log.action.lower() %}admin-log{% endif %}">
                        <td>{{ log.time }}</td>
                        <td>{{ log.action }}</td>
                        <td>{{ log.ip }}</td>
                        <td>{{ log.location }}</td>
                        <td>
                            {% if log.device == 'Windows' %}
                            <span class="device-icon">💻</span>
                            {% elif log.device == 'Android' %}
                            <span class="device-icon">📱</span>
                            {% elif log.device == 'iOS' %}
                            <span class="device-icon">🍎</span>
                            {% elif log.device == 'Mac' %}
                            <span class="device-icon">🖥️</span>
                            {% elif log.device == 'Linux' %}
                            <span class="device-icon">🐧</span>
                            {% else %}
                            <span class="device-icon">❓</span>
                            {% endif %}
                            {{ log.device }}
                        </td>
                        <td>{{ log.browser }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <a href="{{ url_for('admin_panel') }}" class="back-btn">Quay lại Admin Panel</a>
        </div>
    </body>
    </html>
    ''', logs=simple_logs)

@app.route("/download_selected", methods=["POST"])
def download_selected():
    """Download selected files as zip"""
    data = request.get_json()
    files = data.get("files", [])
    
    if not files:
        return "Không có file nào được chọn", 400
    
    # Check for password-protected files
    protected_files = []
    for file in files:
        folder = file.get("folder", "root")
        filename = file.get("name")
        key = f"{folder}/{filename}" if folder != "root" else filename
        if key in file_passwords:
            protected_files.append(filename)
    
    if protected_files:
        return f"Các file sau được bảo vệ: {', '.join(protected_files)}. Vui lòng tải riêng từng file.", 400
    
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in files:
            folder = file.get("folder", "root")
            filename = file.get("name")
            
            if folder == "root":
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            else:
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], folder, filename)
            
            if os.path.exists(filepath):
                relative_path = os.path.join(folder, filename) if folder != "root" else filename
                zf.write(filepath, relative_path)
    
    zip_buffer.seek(0)
    log_access(request.remote_addr, request.user_agent.string, f"Tải xuống {len(files)} file đã chọn")
    return send_file(zip_buffer, mimetype="application/zip", as_attachment=True, download_name="selected_files.zip")

@app.route("/download_bulk")
def download_bulk():
    """Download all files as zip (excluding password-protected ones)"""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root_dir, dirs, files in os.walk(app.config["UPLOAD_FOLDER"]):
            for file in files:
                file_path = os.path.join(root_dir, file)
                relative_path = os.path.relpath(file_path, app.config["UPLOAD_FOLDER"])
                
                # Skip password-protected files
                if relative_path in file_passwords:
                    continue
                
                zf.write(file_path, relative_path)
    
    zip_buffer.seek(0)
    log_access(request.remote_addr, request.user_agent.string, "Tải xuống tất cả file")
    return send_file(zip_buffer, mimetype="application/zip", as_attachment=True, download_name="all_files.zip")

@app.route("/view/<folder>/<filename>")
def view_file(folder, filename):
    """View file with appropriate viewer"""
    allowed_image_extensions = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
    allowed_video_extensions = {"mp4", "avi", "mov", "wmv", "flv", "webm", "mkv"}
    allowed_text_extensions = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "json", "xml", "html", "htm", "js", "css", "py"}
    
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    is_image = ext in allowed_image_extensions
    is_video = ext in allowed_video_extensions
    is_text = ext in allowed_text_extensions
    
    # Check if password protected
    key = f"{folder}/{filename}" if folder != "root" else filename
    if key in file_passwords:
        provided = request.args.get('password', '')
        if provided != file_passwords[key]:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Nhập mật khẩu</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .password-box { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
                        h2 { margin-top: 0; color: #333; }
                        input[type="password"] { padding: 10px; margin: 15px 0; width: 200px; border: 1px solid #ddd; border-radius: 5px; }
                        button { padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
                    </style>
                </head>
                <body>
                    <div class="password-box">
                        <h2>File này được bảo vệ</h2>
                        <p>Vui lòng nhập mật khẩu để tiếp tục:</p>
                        <form method="get" action="{{ url_for('view_file', folder=folder, filename=filename) }}">
                            <input type="password" name="password" required>
                            <button type="submit">Xác nhận</button>
                        </form>
                    </div>
                </body>
                </html>
            ''', folder=folder, filename=filename)
    
    # Get file info
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], folder, filename) if folder != "root" else os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    if not os.path.exists(filepath):
        abort(404)
    
    file_size = os.path.getsize(filepath)
    last_modified = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Format file size
    file_size_str = format_file_size(file_size)
    
    # Get file type
    file_type = {
        **{ext: "Hình ảnh" for ext in allowed_image_extensions},
        **{ext: "Video" for ext in allowed_video_extensions},
        **{ext: "Tài liệu" for ext in allowed_text_extensions}
    }.get(ext, "File không xác định")
    
    # Read text content if text file
    file_content = ""
    if is_text and file_size < 1024*1024:  # Only read files < 1MB
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                file_content = f.read()
        except:
            try:
                with open(filepath, "r", encoding="latin-1") as f:
                    file_content = f.read()
            except:
                file_content = "Không thể đọc nội dung file"
    
    log_access(request.remote_addr, request.user_agent.string, f"Xem file {filename}", False, filename)
    return render_template_string(
        VIEW_TEMPLATE,
        filename=filename,
        folder=folder,
        is_image=is_image,
        is_video=is_video,
        is_text=is_text,
        file_content=file_content,
        file_size=file_size_str,
        file_type=file_type,
        last_modified=last_modified,
        admin_logged_in=session.get("admin_logged_in", False)
    )

@app.route("/download/<folder>/<filename>")
def download_file(folder, filename):
    """Download a file with password check"""
    key = f"{folder}/{filename}" if folder != "root" else filename
    if key in file_passwords:
        provided = request.args.get('password', '')
        if provided != file_passwords[key]:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Nhập mật khẩu</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .password-box { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
                        h2 { margin-top: 0; color: #333; }
                        input[type="password"] { padding: 10px; margin: 15px 0; width: 200px; border: 1px solid #ddd; border-radius: 5px; }
                        button { padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
                    </style>
                </head>
                <body>
                    <div class="password-box">
                        <h2>File này được bảo vệ</h2>
                        <p>Vui lòng nhập mật khẩu để tải xuống:</p>
                        <form method="get" action="{{ url_for('download_file', folder=folder, filename=filename) }}">
                            <input type="password" name="password" required>
                            <button type="submit">Xác nhận</button>
                        </form>
                    </div>
                </body>
                </html>
            ''', folder=folder, filename=filename)
    
    directory = app.config["UPLOAD_FOLDER"] if folder == "root" else os.path.join(app.config["UPLOAD_FOLDER"], folder)
    log_access(request.remote_addr, request.user_agent.string, f"Tải xuống file {filename}", False, filename)
    return send_from_directory(directory, filename, as_attachment=True)

@app.route("/create_folder", methods=["POST"])
def create_folder():
    """Create a new folder"""
    folder_name = request.form.get("folder_name", "")
    folder_name = custom_secure_filename(folder_name)
    
    if not folder_name:
        return "Tên folder không hợp lệ", 400
    
    folder_path = os.path.join(app.config["UPLOAD_FOLDER"], folder_name)
    
    if os.path.exists(folder_path):
        return "Folder đã tồn tại", 400
    
    os.makedirs(folder_path, exist_ok=True)
    log_access(request.remote_addr, request.user_agent.string, f"Tạo folder {folder_name}")
    return redirect(url_for('index'))

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file uploads"""
    if "file" not in request.files:
        return "Không có file nào được chọn", 400
    
    file_list = request.files.getlist("file")
    if not file_list or all(f.filename == "" for f in file_list):
        return "Không có file nào được chọn", 400
    
    folder = request.form.get("folder", "root")
    file_password = request.form.get("file_password", "")
    
    if folder == "root":
        save_folder = app.config["UPLOAD_FOLDER"]
    else:
        save_folder = os.path.join(app.config["UPLOAD_FOLDER"], folder)
        os.makedirs(save_folder, exist_ok=True)
    
    uploaded_files = []
    
    for file in file_list:
        if file.filename == "":
            continue
        
        filename = custom_secure_filename(file.filename)
        save_path = os.path.join(save_folder, filename)
        file.save(save_path)
        uploaded_files.append(filename)
        
        if file_password:
            key = f"{folder}/{filename}" if folder != "root" else filename
            file_passwords[key] = file_password
    
    if file_password:
        save_passwords()
    
    log_access(request.remote_addr, request.user_agent.string, f"Tải lên {len(uploaded_files)} file: {', '.join(uploaded_files)}")
    return "Tải lên thành công", 200

@app.route("/preview")
def preview():
    """Preview all files with thumbnails"""
    grouped_files = get_files_grouped()
    allowed_image_extensions = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
    allowed_video_extensions = {"mp4", "avi", "mov", "wmv", "flv", "webm", "mkv"}
    allowed_text_extensions = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "json", "xml", "html", "htm", "js", "css", "py"}
    
    images = []
    videos = []
    texts = []
    others = []
    
    for folder, file_list in grouped_files.items():
        for file in file_list:
            ext = file["name"].rsplit('.', 1)[-1].lower() if '.' in file["name"] else ''
            key = file["name"] if folder == "root" else f"{folder}/{file['name']}"
            is_protected = key in file_passwords
            
            # Get file info
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], folder, file["name"]) if folder != "root" else os.path.join(app.config["UPLOAD_FOLDER"], file["name"])
            file_size = os.path.getsize(filepath)
            
            file_data = {
                "name": file["name"],
                "folder": folder,
                "protected": is_protected,
                "size": format_file_size(file_size)
            }
            
            if ext in allowed_image_extensions:
                images.append(file_data)
            elif ext in allowed_video_extensions:
                videos.append(file_data)
            elif ext in allowed_text_extensions:
                texts.append(file_data)
            else:
                others.append(file_data)
    
    log_access(request.remote_addr, request.user_agent.string, "Xem trang preview")
    return render_template_string(
        PREVIEW_TEMPLATE,
        images=images,
        videos=videos,
        texts=texts,
        others=others,
        admin_logged_in=session.get("admin_logged_in", False)
    )

@app.before_request
def before_request():
    """Log all requests to admin panel"""
    if request.path.startswith('/admin') and not request.path.endswith('/login'):
        if not session.get("admin_logged_in") and request.method == "GET":
            log_access(request.remote_addr, request.user_agent.string, "Truy cập trang admin không được phép")

# --------------------- TEMPLATES ---------------------

INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>File Server của TienKJ</title>
  <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.6.0/dist/confetti.browser.min.js"></script>
  <style>
    @keyframes changeBackground { 0% { background: #ff0000; } 20% { background: #ff8000; } 40% { background: #ffff00; } 60% { background: #00ff00; } 80% { background: #0000ff; } 100% { background: #ff00ff; } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes zoomIn { from { transform: scale(0.8); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    body { font-family: 'Arial', sans-serif; text-align: center; margin: 0; padding: 0; color: white; animation: changeBackground 6s infinite alternate ease-in-out; background-attachment: fixed; }
    .container { width: 90%; max-width: 1000px; margin: 40px auto; padding: 20px; background: rgba(0,0,0,0.7); border-radius: 15px; box-shadow: 0 8px 20px rgba(0,0,0,0.5); animation: fadeIn 1s ease-in-out; backdrop-filter: blur(5px); }
    h1 { font-size: 28px; margin-bottom: 20px; text-transform: uppercase; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
    form { margin: 20px 0; }
    input[type="text"], select, input[type="file"], input[type="password"] { 
      padding: 10px; 
      margin: 8px 5px; 
      border-radius: 8px; 
      border: none; 
      max-width: 100%; 
      width: 300px;
      font-size: 16px;
    }
    input[type="file"] { 
      display: block; 
      margin: 10px auto; 
      padding: 15px;
      border: 2px dashed #fff;
      border-radius: 10px;
      background: rgba(255,255,255,0.1);
    }
    .btn { 
      background: linear-gradient(45deg, #ff7eb3, #ff527b);
      color: white; 
      border: none; 
      padding: 12px 25px; 
      cursor: pointer; 
      border-radius: 8px; 
      transition: all 0.3s; 
      font-size: 16px;
      font-weight: bold;
      margin: 5px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .btn:hover { 
      transform: translateY(-3px) scale(1.05); 
      box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    .btn-admin { 
      background: linear-gradient(45deg, #ff0000, #cc0000);
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 100;
    }
    .progress-container { 
      width: 100%; 
      background: rgba(255,255,255,0.2); 
      border-radius: 10px; 
      overflow: hidden; 
      display: none; 
      margin: 15px 0;
      height: 15px;
    }
    .progress-bar { 
      width: 0%; 
      height: 100%; 
      background: linear-gradient(90deg, #4caf50, #8bc34a);
      transition: width 0.3s; 
    }
    .speed { 
      margin-top: 5px; 
      font-size: 14px; 
      color: #ddd;
    }
    .file-group { 
      margin: 25px 0; 
      text-align: left; 
      background: rgba(0,0,0,0.4);
      padding: 15px;
      border-radius: 10px;
    }
    .file-group h3 { 
      margin-bottom: 15px; 
      color: #ffd700;
      border-bottom: 1px solid #ffd700;
      padding-bottom: 5px;
    }
    ul { 
      list-style: none; 
      padding-left: 0; 
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 10px;
    }
    li { 
      background: rgba(255,255,255,0.15); 
      margin: 5px 0; 
      padding: 12px; 
      border-radius: 8px; 
      animation: zoomIn 0.5s ease; 
      transition: all 0.3s;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    li:hover { 
      transform: scale(1.03); 
      background: rgba(255,255,255,0.25);
      box-shadow: 0 4px 10px rgba(0,0,0,0.3); 
    }
    a { 
      color: #ffd700; 
      text-decoration: none; 
      transition: color 0.3s; 
      word-wrap: break-word;
    }
    a:hover { 
      color: #fff; 
      text-decoration: underline;
    }
    .file-actions {
      display: flex;
      gap: 10px;
      margin-left: 10px;
    }
    .file-actions a {
      white-space: nowrap;
    }
    .file-actions .delete-btn {
      color: #ff4444;
    }
    .file-actions .delete-btn:hover {
      color: #cc0000;
      text-decoration: underline;
    }
    .admin-only { display: none; }
    {% if admin_logged_in %}
    .admin-only { display: inline-block; }
    {% endif %}
    @media (max-width: 768px) { 
      h1 { font-size: 24px; } 
      .container { padding: 15px; width: 95%; } 
      .btn { padding: 10px 15px; } 
      li { font-size: 14px; }
      ul { grid-template-columns: 1fr; }
    }
    .notification {
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: rgba(0,0,0,0.8);
      color: white;
      padding: 15px 25px;
      border-radius: 8px;
      z-index: 1000;
      display: none;
    }
  </style>
</head>
<body>
  <div class="notification" id="notification"></div>
  <a href="{{ url_for('admin_panel') }}" class="btn btn-admin">Admin</a>
  
  <div class="container">
    <h1>File Server của TienKJ</h1>
    
    <!-- Form tạo folder -->
    <form id="create-folder-form" action="/create_folder" method="post">
      <input type="text" name="folder_name" placeholder="Tên folder mới" required>
      <button type="submit" class="btn">Tạo folder</button>
    </form>
    
    <!-- Form tải file -->
    <form id="upload-form" action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="file" multiple required>
      <select name="folder">
        <option value="root">Chọn folder (Root)</option>
        {% for folder in folders %}
          <option value="{{ folder }}">{{ folder }}</option>
        {% endfor %}
      </select>
      <input type="password" name="file_password" placeholder="Mật khẩu (nếu cần)">
      <button type="submit" class="btn">Tải lên server</button>
    </form>
    
    <div class="progress-container" id="progress-container">
      <div class="progress-bar" id="progress-bar"></div>
      <div class="speed" id="speed"></div>
    </div>
    
    <!-- Hiển thị danh sách file -->
    <div class="file-group">
      <h3>Files trong Root:</h3>
      <ul>
      {% for file in files.root %}
        <li>
          <a href="{{ url_for('view_file', folder='root', filename=file.name) }}" title="{{ file.name }}">
            {{ file.name|truncate(30, True) }}
          </a>
          <div class="file-actions">
            {% if file.viewable or file.text %}
              <a href="{{ url_for('view_file', folder='root', filename=file.name) }}">Xem</a>
            {% endif %}
            <a href="{{ url_for('download_file', folder='root', filename=file.name) }}">Tải</a>
            <a href="#" class="delete-btn admin-only" onclick="deleteFile('root', '{{ file.name }}')">Xóa</a>
          </div>
        </li>
      {% endfor %}
      </ul>
    </div>
    
    {% for folder, file_list in files.items() %}
      {% if folder != 'root' %}
      <div class="file-group">
        <h3>Folder: {{ folder }}</h3>
        <ul>
        {% for file in file_list %}
          <li>
            <a href="{{ url_for('view_file', folder=folder, filename=file.name) }}" title="{{ file.name }}">
              {{ file.name|truncate(30, True) }}
            </a>
            <div class="file-actions">
              {% if file.viewable or file.text %}
                <a href="{{ url_for('view_file', folder=folder, filename=file.name) }}">Xem</a>
              {% endif %}
              <a href="{{ url_for('download_file', folder=folder, filename=file.name) }}">Tải</a>
              <a href="#" class="delete-btn admin-only" onclick="deleteFile('{{ folder }}', '{{ file.name }}')">Xóa</a>
            </div>
          </li>
        {% endfor %}
        </ul>
      </div>
      {% endif %}
    {% endfor %}
    
    <div style="margin-top: 30px; display: flex; justify-content: center; gap: 15px; flex-wrap: wrap;">
      <a href="{{ url_for('preview') }}" class="btn">Xem Preview</a>
      <a href="{{ url_for('download_bulk') }}" class="btn">Tải xuống tất cả</a>
      <a href="{{ url_for('view_logs') }}" class="btn admin-only">Xem lịch sử truy cập</a>
    </div>
  </div>
  
  <script>
    function showNotification(message, isSuccess = true) {
      const notification = document.getElementById('notification');
      notification.textContent = message;
      notification.style.backgroundColor = isSuccess ? 'rgba(76, 175, 80, 0.9)' : 'rgba(244, 67, 54, 0.9)';
      notification.style.display = 'block';
      
      setTimeout(() => {
        notification.style.display = 'none';
      }, 3000);
    }
    
    document.getElementById("upload-form").addEventListener("submit", function(event) {
      event.preventDefault();
      let formData = new FormData(this);
      let xhr = new XMLHttpRequest();
      let progressBar = document.getElementById("progress-bar");
      let progressContainer = document.getElementById("progress-container");
      let speedText = document.getElementById("speed");
      let startTime = new Date().getTime();
      progressContainer.style.display = "block";
      
      xhr.open("POST", "/upload", true);
      
      xhr.upload.onprogress = function(event) {
        if (event.lengthComputable) {
          let percent = (event.loaded / event.total) * 100;
          progressBar.style.width = percent + "%";
          let timeElapsed = (new Date().getTime() - startTime) / 1000;
          let speed = (event.loaded / 1024 / timeElapsed).toFixed(2);
          speedText.textContent = `Tốc độ: ${speed} KB/s`;
        }
      };
      
      xhr.onload = function() {
        if (xhr.status == 200) {
          confetti({ particleCount: 150, spread: 70, origin: { y: 0.6 } });
          showNotification("Tải lên file thành công!");
          setTimeout(function() {
            location.reload();
          }, 1000);
        } else {
          showNotification("Có lỗi khi tải lên: " + xhr.responseText, false);
        }
      };
      
      xhr.onerror = function() {
        showNotification("Lỗi kết nối khi tải lên", false);
      };
      
      xhr.send(formData);
    });
    
    // Handle folder creation feedback
    const folderForm = document.getElementById("create-folder-form");
    if (folderForm) {
      folderForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        
        try {
          const response = await fetch(this.action, {
            method: 'POST',
            body: formData
          });
          
          if (response.ok) {
            showNotification("Tạo folder thành công!");
            setTimeout(() => location.reload(), 1000);
          } else {
            const error = await response.text();
            showNotification(error, false);
          }
        } catch (err) {
          showNotification("Lỗi kết nối", false);
        }
      });
    }
    
    // Add delete file functionality
    function deleteFile(folder, filename) {
      if (!confirm(`Bạn chắc chắn muốn xóa file ${filename}?`)) {
        return;
      }
      
      fetch("{{ url_for('delete_file') }}", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          folder: folder,
          filename: filename
        })
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          showNotification(`Đã xóa file ${filename}`);
          setTimeout(() => location.reload(), 1000);
        } else {
          showNotification(`Lỗi: ${data.message}`, false);
        }
      })
      .catch(error => {
        showNotification(`Lỗi: ${error}`, false);
      });
    }
  </script>
</body>
</html>
'''

PREVIEW_TEMPLATE = '''
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Preview Files</title>
  <style>
    body {
      font-family: 'Arial', sans-serif;
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      margin: 0;
      padding: 20px;
      min-height: 100vh;
    }
    .toolbar {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 15px;
      margin-bottom: 30px;
      padding: 15px;
      background: rgba(0,0,0,0.3);
      border-radius: 10px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .toolbar .btn {
      background: linear-gradient(45deg, #ff7eb3, #ff527b);
      color: white;
      border: none;
      padding: 12px 25px;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.3s;
      font-weight: bold;
      min-width: 150px;
      text-align: center;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .toolbar .btn:hover {
      transform: translateY(-3px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    section { 
      margin-bottom: 40px;
      background: rgba(0,0,0,0.3);
      padding: 20px;
      border-radius: 15px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    section h3 {
      margin-bottom: 20px;
      color: #ffd700;
      font-size: 24px;
      text-align: center;
      text-shadow: 0 2px 4px rgba(0,0,0,0.3);
      border-bottom: 2px solid #ffd700;
      padding-bottom: 10px;
    }
    .preview-gallery {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 20px;
      justify-content: center;
    }
    .preview-item {
      position: relative;
      background: rgba(255,255,255,0.1);
      padding: 15px;
      border-radius: 10px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
      transition: all 0.3s;
      overflow: hidden;
    }
    .preview-item:hover { 
      transform: translateY(-5px);
      box-shadow: 0 8px 20px rgba(0,0,0,0.3);
      background: rgba(255,255,255,0.15);
    }
    .preview-item img, .preview-item video {
      width: 100%;
      border-radius: 8px;
      display: block;
      aspect-ratio: 16/9;
      object-fit: cover;
    }
    .select-container {
      position: absolute;
      top: 10px;
      left: 10px;
      z-index: 10;
      background: rgba(0,0,0,0.7);
      padding: 5px;
      border-radius: 5px;
    }
    .select-container input[type="checkbox"] { 
      width: 20px; 
      height: 20px; 
      cursor: pointer;
    }
    .unsupported-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      min-height: 200px;
      background: rgba(0,0,0,0.2);
      border-radius: 8px;
    }
    .unsupported-item p {
      margin: 10px 0;
      font-weight: bold;
      word-break: break-word;
      padding: 0 10px;
    }
    .unsupported-item .btn { 
      margin-top: 10px;
      padding: 8px 15px;
      background: #ff7eb3;
      color: white;
      border-radius: 5px;
      text-decoration: none;
      transition: all 0.3s;
    }
    .unsupported-item .btn:hover {
      background: #ff527b;
      transform: translateY(-2px);
    }
    .file-info {
      margin-top: 10px;
      font-size: 14px;
      color: #ccc;
    }
    .protected-badge {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(255,0,0,0.7);
      color: white;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 10;
    }
    @media (max-width: 768px) {
      .preview-gallery {
        grid-template-columns: 1fr;
      }
      .toolbar .btn {
        min-width: 120px;
        padding: 10px 15px;
      }
    }
    .empty-message {
      text-align: center;
      padding: 20px;
      color: #ccc;
      font-style: italic;
      grid-column: 1 / -1;
    }
    .admin-only { display: none; }
    {% if admin_logged_in %}
    .admin-only { display: inline-block; }
    {% endif %}
  </style>
</head>
<body>
  <div class="toolbar">
    <button class="btn" onclick="filterFiles('image')">Hình ảnh</button>
    <button class="btn" onclick="filterFiles('video')">Video</button>
    <button class="btn" onclick="filterFiles('text')">Tài liệu</button>
    <button class="btn" onclick="filterFiles('other')">Khác</button>
    <button class="btn" onclick="filterFiles('all')">Tất cả</button>
    <button class="btn" onclick="window.location.href='{{ url_for('index') }}'">Quay lại</button>
    <button class="btn" onclick="downloadSelected()">Tải đã chọn</button>
    <a href="{{ url_for('view_logs') }}" class="btn admin-only">Xem logs</a>
  </div>

  <section id="section-image">
    <h3>Hình ảnh ({{ images|length }})</h3>
    <div class="preview-gallery">
      {% if images|length == 0 %}
        <div class="empty-message">Không có hình ảnh nào</div>
      {% endif %}
      {% for file in images %}
        <div class="preview-item" data-type="image">
          {% if file.protected %}
          <div class="protected-badge">Bảo mật</div>
          {% endif %}
          <div class="select-container">
            <input type="checkbox" class="select-file" data-folder="{{ file.folder }}" data-name="{{ file.name }}" {% if file.protected %}disabled title="File được bảo vệ"{% endif %}>
          </div>
          <a href="{{ url_for('view_file', folder=file.folder, filename=file.name) }}" class="preview-link">
            <img src="{{ url_for('download_file', folder=file.folder, filename=file.name) }}" alt="{{ file.name }}" loading="lazy">
          </a>
          <div class="file-info">
            <p>{{ file.name|truncate(20) }}</p>
            <p>{{ file.size }}</p>
          </div>
          {% if admin_logged_in %}
          <div style="text-align: center; margin-top: 10px;">
            <a href="#" class="btn" style="padding: 5px 10px; font-size: 12px;" onclick="deleteFile('{{ file.folder }}', '{{ file.name }}')">Xóa</a>
          </div>
          {% endif %}
        </div>
      {% endfor %}
    </div>
  </section>

  <section id="section-video">
    <h3>Video ({{ videos|length }})</h3>
    <div class="preview-gallery">
      {% if videos|length == 0 %}
        <div class="empty-message">Không có video nào</div>
      {% endif %}
      {% for file in videos %}
        <div class="preview-item" data-type="video">
          {% if file.protected %}
          <div class="protected-badge">Bảo mật</div>
          {% endif %}
          <div class="select-container">
            <input type="checkbox" class="select-file" data-folder="{{ file.folder }}" data-name="{{ file.name }}" {% if file.protected %}disabled title="File được bảo vệ"{% endif %}>
          </div>
          <a href="{{ url_for('view_file', folder=file.folder, filename=file.name) }}" class="preview-link">
            <video controls preload="metadata">
              <source src="{{ url_for('download_file', folder=file.folder, filename=file.name) }}" type="video/mp4">
              Trình duyệt không hỗ trợ video.
            </video>
          </a>
          <div class="file-info">
            <p>{{ file.name|truncate(20) }}</p>
            <p>{{ file.size }}</p>
          </div>
          {% if admin_logged_in %}
          <div style="text-align: center; margin-top: 10px;">
            <a href="#" class="btn" style="padding: 5px 10px; font-size: 12px;" onclick="deleteFile('{{ file.folder }}', '{{ file.name }}')">Xóa</a>
          </div>
          {% endif %}
        </div>
      {% endfor %}
    </div>
  </section>

  <section id="section-text">
    <h3>Tài liệu ({{ texts|length }})</h3>
    <div class="preview-gallery">
      {% if texts|length == 0 %}
        <div class="empty-message">Không có tài liệu nào</div>
      {% endif %}
      {% for file in texts %}
        <div class="preview-item unsupported-item" data-type="text">
          {% if file.protected %}
          <div class="protected-badge">Bảo mật</div>
          {% endif %}
          <div class="select-container">
            <input type="checkbox" class="select-file" data-folder="{{ file.folder }}" data-name="{{ file.name }}" {% if file.protected %}disabled title="File được bảo vệ"{% endif %}>
          </div>
          <p>{{ file.name }}</p>
          <p>{{ file.size }}</p>
          <div style="display: flex; gap: 10px; margin-top: 10px;">
            <a href="{{ url_for('view_file', folder=file.folder, filename=file.name) }}" class="btn">Xem</a>
            <a href="{{ url_for('download_file', folder=file.folder, filename=file.name) }}" class="btn">Tải</a>
            {% if admin_logged_in %}
            <a href="#" class="btn" style="background: #ff4444;" onclick="deleteFile('{{ file.folder }}', '{{ file.name }}')">Xóa</a>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </div>
  </section>

  <section id="section-other">
    <h3>Khác ({{ others|length }})</h3>
    <div class="preview-gallery">
      {% if others|length == 0 %}
        <div class="empty-message">Không có file nào</div>
      {% endif %}
      {% for file in others %}
        <div class="preview-item unsupported-item" data-type="other">
          {% if file.protected %}
          <div class="protected-badge">Bảo mật</div>
          {% endif %}
          <div class="select-container">
            <input type="checkbox" class="select-file" data-folder="{{ file.folder }}" data-name="{{ file.name }}" {% if file.protected %}disabled title="File được bảo vệ"{% endif %}>
          </div>
          <p>{{ file.name }}</p>
          <p>{{ file.size }}</p>
          <div style="display: flex; gap: 10px; margin-top: 10px;">
            <a href="{{ url_for('download_file', folder=file.folder, filename=file.name) }}" class="btn">Tải xuống</a>
            {% if admin_logged_in %}
            <a href="#" class="btn" style="background: #ff4444;" onclick="deleteFile('{{ file.folder }}', '{{ file.name }}')">Xóa</a>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </div>
  </section>

  <script>
    function filterFiles(type) {
      document.querySelectorAll('.preview-item').forEach(item => {
        if (type === 'all') {
          item.style.display = 'block';
        } else {
          item.style.display = item.getAttribute('data-type') === type ? 'block' : 'none';
        }
      });
      
      // Smooth scroll to the first visible section
      if (type !== 'all') {
        const firstSection = document.getElementById(`section-${type}`);
        if (firstSection) {
          firstSection.scrollIntoView({ behavior: 'smooth' });
        }
      }
    }

    document.querySelectorAll('.preview-link').forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        document.body.style.opacity = 0;
        document.body.style.transition = 'opacity 0.3s';
        setTimeout(() => {
          window.location.href = link.href;
        }, 300);
      });
    });

    function deleteFile(folder, filename) {
      if (!confirm(`Bạn chắc chắn muốn xóa file ${filename}?`)) {
        return;
      }
      
      fetch("{{ url_for('delete_file') }}", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          folder: folder,
          filename: filename
        })
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert(`Đã xóa file ${filename}`);
          location.reload();
        } else {
          alert(`Lỗi: ${data.message}`);
        }
      })
      .catch(error => {
        alert(`Lỗi: ${error}`);
      });
    }

    function downloadSelected() {
      const selectedFiles = Array.from(document.querySelectorAll('.select-file:checked'))
        .map(checkbox => ({
          folder: checkbox.dataset.folder,
          name: checkbox.dataset.name
        }));

      if (selectedFiles.length === 0) {
        alert("Vui lòng chọn ít nhất một file.");
        return;
      }

      const downloadBtn = document.querySelector('[onclick="downloadSelected()"]');
      downloadBtn.disabled = true;
      downloadBtn.textContent = "Đang chuẩn bị...";

      fetch("{{ url_for('download_selected') }}", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files: selectedFiles })
      })
      .then(response => {
        if (!response.ok) {
          return response.text().then(text => { throw new Error(text) });
        }
        return response.blob();
      })
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = "selected_files.zip";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      })
      .catch(err => {
        console.error(err);
        alert(err.message || "Có lỗi xảy ra khi tải file.");
      })
      .finally(() => {
        downloadBtn.disabled = false;
        downloadBtn.textContent = "Tải đã chọn";
      });
    }

    // Initialize - show all files
    filterFiles('all');
  </script>
</body>
</html>
'''

VIEW_TEMPLATE = '''
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Xem file: {{ filename }}</title>
  <style>
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    body { 
      font-family: 'Arial', sans-serif; 
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: white;
      margin: 0;
      padding: 20px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      animation: fadeIn 0.5s ease;
    }
    .container { 
      max-width: 900px; 
      width: 100%;
      background: rgba(0,0,0,0.5);
      padding: 30px;
      border-radius: 15px;
      box-shadow: 0 8px 25px rgba(0,0,0,0.3);
      margin-top: 30px;
    }
    h1 { 
      font-size: 24px; 
      margin-bottom: 25px; 
      color: #ffd700;
      text-align: center;
      word-break: break-word;
    }
    .media-container {
      width: 100%;
      display: flex;
      justify-content: center;
      margin-bottom: 25px;
    }
    .media-container img {
      max-width: 100%;
      max-height: 70vh;
      border-radius: 10px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .media-container video {
      max-width: 100%;
      max-height: 70vh;
      border-radius: 10px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .text-content {
      background: rgba(0,0,0,0.3);
      padding: 20px;
      border-radius: 10px;
      white-space: pre-wrap;
      font-family: monospace;
      max-height: 60vh;
      overflow-y: auto;
    }
    .download-btn { 
      display: inline-block;
      background: linear-gradient(45deg, #ff7eb3, #ff527b);
      color: white; 
      padding: 12px 30px; 
      text-decoration: none; 
      border-radius: 8px; 
      margin-top: 20px;
      transition: all 0.3s;
      font-weight: bold;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .download-btn:hover { 
      transform: translateY(-3px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    .back-btn {
      position: fixed;
      top: 20px;
      left: 20px;
      background: rgba(0,0,0,0.5);
      color: white;
      padding: 10px 15px;
      border-radius: 5px;
      text-decoration: none;
      z-index: 100;
    }
    .back-btn:hover {
      background: rgba(0,0,0,0.7);
    }
    @media (max-width: 768px) {
      .container { padding: 15px; }
      h1 { font-size: 20px; }
      .download-btn { padding: 10px 20px; }
    }
    .unsupported-file {
      text-align: center;
      padding: 40px 0;
    }
    .file-info {
      margin-top: 20px;
      padding: 15px;
      background: rgba(0,0,0,0.3);
      border-radius: 10px;
    }
    .file-info p {
      margin: 5px 0;
    }
    .admin-actions {
      margin-top: 20px;
      text-align: center;
    }
    .delete-btn {
      background: #ff4444 !important;
      margin-left: 10px;
    }
  </style>
</head>
<body>
  <a href="{{ url_for('preview') }}" class="back-btn">← Quay lại</a>
  
  <div class="container">
    <h1>{{ filename }}</h1>
    
    {% if is_image %}
      <div class="media-container">
        <img src="{{ url_for('download_file', folder=folder, filename=filename) }}" alt="{{ filename }}">
      </div>
    {% elif is_video %}
      <div class="media-container">
        <video controls autoplay>
          <source src="{{ url_for('download_file', folder=folder, filename=filename) }}">
          Trình duyệt không hỗ trợ video.
        </video>
      </div>
    {% elif is_text %}
      <div class="text-content">
        {{ file_content }}
      </div>
    {% else %}
      <div class="unsupported-file">
        <p>Không thể hiển thị file này</p>
      </div>
    {% endif %}
    
    <div class="file-info">
      <p><strong>Kích thước:</strong> {{ file_size }}</p>
      <p><strong>Loại file:</strong> {{ file_type }}</p>
      <p><strong>Lần cuối sửa:</strong> {{ last_modified }}</p>
    </div>
    
    <div style="text-align: center; margin-top: 30px;">
      <a class="download-btn" href="{{ url_for('download_file', folder=folder, filename=filename) }}">Tải xuống</a>
      {% if admin_logged_in %}
      <a class="download-btn delete-btn" href="#" onclick="deleteFile('{{ folder }}', '{{ filename }}')">Xóa file</a>
      {% endif %}
    </div>
  </div>

  <script>
    function deleteFile(folder, filename) {
      if (!confirm(`Bạn chắc chắn muốn xóa file ${filename}?`)) {
        return;
      }
      
      fetch("{{ url_for('delete_file') }}", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          folder: folder,
          filename: filename
        })
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert(`Đã xóa file ${filename}`);
          window.location.href = "{{ url_for('preview') }}";
        } else {
          alert(`Lỗi: ${data.message}`);
        }
      })
      .catch(error => {
        alert(`Lỗi: ${error}`);
      });
    }
  </script>
</body>
</html>
'''

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel</title>
  <style>
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
    body { 
      font-family: 'Arial', sans-serif; 
      margin: 0; 
      padding: 0; 
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      animation: fadeIn 0.5s ease;
    }
    .header { 
      background: linear-gradient(45deg, #ff0000, #cc0000);
      color: white; 
      padding: 20px; 
      text-align: center;
      box-shadow: 0 4px 15px rgba(0,0,0,0.3);
      position: relative;
    }
    .container { 
      max-width: 1200px; 
      margin: 0 auto; 
      padding: 20px;
    }
    .controls { 
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 15px;
      margin: 25px 0;
    }
    .controls a { 
      display: inline-block; 
      padding: 12px 25px; 
      background: linear-gradient(45deg, #ff7eb3, #ff527b);
      color: white; 
      text-decoration: none; 
      border-radius: 8px; 
      transition: all 0.3s;
      font-weight: bold;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .controls a:hover { 
      transform: translateY(-3px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.3);
    }
    .controls a.danger { 
      background: linear-gradient(45deg, #ff0000, #cc0000);
    }
    .log-container { 
      background: rgba(0,0,0,0.3);
      border-radius: 15px;
      padding: 20px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
      margin-bottom: 30px;
    }
    .log-entry { 
      margin-bottom: 20px; 
      padding: 15px; 
      background: rgba(0,0,0,0.2);
      border-radius: 10px;
      transition: all 0.3s;
    }
    .log-entry:hover {
      background: rgba(0,0,0,0.4);
      transform: translateY(-3px);
    }
    .log-entry.admin { 
      border-left: 5px solid #ff0000;
    }
    .log-entry h3 { 
      margin-top: 0; 
      color: #ffd700;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
    }
    .log-details { 
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 15px;
      margin-top: 10px;
    }
    .log-details p { 
      margin: 5px 0;
      word-break: break-word;
    }
    .geo-info { 
      background: rgba(0,0,0,0.2);
      padding: 10px;
      border-radius: 8px;
    }
    .pagination { 
      display: flex;
      justify-content: center;
      gap: 10px;
      margin-top: 20px;
    }
    .pagination a { 
      padding: 8px 15px;
      background: rgba(0,0,0,0.3);
      border-radius: 5px;
      text-decoration: none;
      color: white;
      transition: all 0.3s;
    }
    .pagination a:hover { 
      background: rgba(0,0,0,0.5);
    }
    .pagination a.active { 
      background: #ff7eb3;
      font-weight: bold;
    }
    .search-box {
      margin: 20px 0;
      display: flex;
      justify-content: center;
    }
    .search-box input {
      padding: 10px 15px;
      border-radius: 8px 0 0 8px;
      border: none;
      width: 300px;
      max-width: 100%;
    }
    .search-box button {
      padding: 10px 15px;
      background: #ff7eb3;
      color: white;
      border: none;
      border-radius: 0 8px 8px 0;
      cursor: pointer;
    }
    @media (max-width: 768px) {
      .controls a { padding: 10px 15px; }
      .log-details { grid-template-columns: 1fr; }
    }
    .empty-logs {
      text-align: center;
      padding: 40px 0;
      color: #ccc;
      font-style: italic;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: rgba(0,0,0,0.3);
      padding: 15px;
      border-radius: 10px;
      text-align: center;
    }
    .stat-card h3 {
      margin-top: 0;
      color: #ffd700;
    }
    .stat-card p {
      font-size: 24px;
      font-weight: bold;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Admin Panel</h1>
    <p>Quản lý hệ thống và xem lịch sử truy cập</p>
  </div>
  
  <div class="container">
    <div class="controls">
      <a href="{{ url_for('delete_all_files') }}" onclick="return confirm('XÓA TẤT CẢ FILE? Hành động này không thể hoàn tác!')" class="danger">Xóa tất cả file</a>
      <a href="{{ url_for('clear_logs') }}" onclick="return confirm('Xóa tất cả logs?')" class="danger">Xóa logs</a>
      <a href="{{ url_for('admin_logout') }}">Đăng xuất</a>
      <a href="{{ url_for('index') }}">Về trang chủ</a>
    </div>
    
    <div class="stats">
      <div class="stat-card">
        <h3>Tổng truy cập</h3>
        <p>{{ total_visits }}</p>
      </div>
      <div class="stat-card">
        <h3>Truy cập hôm nay</h3>
        <p>{{ today_visits }}</p>
      </div>
      <div class="stat-card">
        <h3>Truy cập admin</h3>
        <p>{{ admin_visits }}</p>
      </div>
      <div class="stat-card">
        <h3>Tải lên</h3>
        <p>{{ upload_count }}</p>
      </div>
    </div>
    
    <div class="search-box">
      <form method="get" action="{{ url_for('admin_panel') }}">
        <input type="text" name="search" placeholder="Tìm theo IP, hành động..." value="{{ search_query }}">
        <button type="submit">Tìm kiếm</button>
      </form>
    </div>
    
    <div class="log-container">
      <h2>Lịch sử truy cập ({{ logs|length }} gần nhất)</h2>
      
      {% if logs|length == 0 %}
        <div class="empty-logs">Không có log nào</div>
      {% endif %}
      
      {% for log in logs %}
        <div class="log-entry {% if log.is_admin %}admin{% endif %}">
          <h3>
            <span>{{ log.timestamp }}</span>
            <span style="color: {% if log.is_admin %}#ff0000{% else %}#4caf50{% endif %}">
              {{ log.action }}
              {% if log.filename %}({{ log.filename }}){% endif %}
            </span>
          </h3>
          
          <div class="log-details">
            <div>
              <p><strong>IP:</strong> {{ log.ip }}</p>
              <p><strong>Thiết bị:</strong> {{ log.user_agent|truncate(50) }}</p>
              <p><strong>Hệ điều hành:</strong> {{ detect_device(log.user_agent) }}</p>
              <p><strong>Trình duyệt:</strong> {{ detect_browser(log.user_agent) }}</p>
            </div>
            
            <div class="geo-info">
              <p><strong>Vị trí:</strong></p>
              <p>{{ log.geo_info.get('city', 'Không rõ') }}, {{ log.geo_info.get('regionName', 'Không rõ') }}, {{ log.geo_info.get('country', 'Không rõ') }}</p>
              <p><strong>ISP:</strong> {{ log.geo_info.get('isp', 'Không rõ') }}</p>
            </div>
          </div>
        </div>
      {% endfor %}
      
      {% if pages > 1 %}
        <div class="pagination">
          {% for page_num in range(1, pages + 1) %}
            <a href="{{ url_for('admin_panel', page=page_num, search=search_query) }}" {% if page_num == page %}class="active"{% endif %}>{{ page_num }}</a>
          {% endfor %}
        </div>
      {% endif %}
    </div>
  </div>
</body>
</html>
'''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)