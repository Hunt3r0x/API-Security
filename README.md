
### API Security Checklist V1.0

---

#### **1. Verify Object-Level Authorization**  
**Why**: Prevent unauthorized access to sensitive data by ensuring users can only access their own objects.  

- [ ] Ensure proper access control for every object in APIs and endpoints.

```python
# Flask example for object-level authorization
@app.route('/api/resource/<int:resource_id>', methods=['GET'])
def get_resource(resource_id):
    resource = get_resource_by_id(resource_id)
    if resource.owner_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    return jsonify(resource.to_dict())
```

---

#### **2. Validate User Authentication**  
**Why**: Ensure only legitimate users can access your API.

- [ ] Implement secure authentication mechanisms (e.g., strong passwords, multi-factor authentication).

```python
# Flask-Login example
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'error': 'Invalid credentials'}), 401
```

---

#### **3. Avoid Excessive Data Exposure**  
**Why**: Minimize risk by exposing only the necessary information in API responses.

- [ ] Only return necessary data in API responses. Filter sensitive fields.

```python
# Flask example
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = get_user_by_id(user_id)
    return jsonify({'id': user.id, 'username': user.username})  # Exclude sensitive fields
```

---

#### **4. Enforce Resource and Rate Limits**  
**Why**: Prevent abuse such as DDoS attacks or brute-force attempts.

- [ ] Implement rate limiting to prevent abuse.

```python
# Flask-Limiter example
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/resource', methods=['GET'])
@limiter.limit("10 per minute")  # Allow only 10 requests per minute per IP
def get_resource():
    return jsonify({'message': 'Resource accessed'})
```

---

#### **5. Check Function-Level Authorization**  
**Why**: Ensure actions and roles are properly restricted.

- [ ] Ensure each function or action has proper access control checks.

```python
# Flask example
@app.route('/api/admin/resource', methods=['POST'])
@admin_required  # Custom decorator to check admin role
def admin_only_action():
    return jsonify({'message': 'Admin action performed'})
```

---

#### **6. Prevent Mass Assignment**  
**Why**: Protect against attackers trying to update unintended fields.

- [ ] Restrict which fields can be updated via APIs.

```python
# Flask example
@app.route('/api/user/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    allowed_fields = {'username', 'email'}
    for field in data.keys():
        if field not in allowed_fields:
            return jsonify({'error': 'Invalid field update'}), 400
    user = get_user_by_id(user_id)
    for key, value in data.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify({'message': 'User updated'})
```

---

#### **7. Fix Security Misconfigurations**  
**Why**: Secure settings prevent common vulnerabilities.

- [ ] Regularly review and apply secure settings.

```python
# Flask example: Enable HTTPS and disable debug mode
if __name__ == "__main__":
    app.run(ssl_context='adhoc', debug=False)
```

---

#### **8. Sanitize Inputs to Avoid Injection**  
**Why**: Prevent SQL, command, or script injection attacks.

- [ ] Validate and sanitize all inputs.

```python
# Flask + SQLAlchemy example
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    if not query.isalnum():  # Basic validation
        return jsonify({'error': 'Invalid query'}), 400
    results = Item.query.filter(Item.name.ilike(f'%{query}%')).all()
    return jsonify([item.to_dict() for item in results])
```

---

#### **9. Manage Assets Properly**  
**Why**: Keep track of vulnerabilities in dependencies and third-party integrations.

- [ ] Keep an updated inventory of all applications, APIs, and third-party integrations.

```bash
# Example of dependency scanning
pip freeze > requirements.txt
pip-audit
```

---

#### **10. Enable Sufficient Logging and Monitoring**  
**Why**: Logs provide critical information for detecting and responding to threats.

- [ ] Log security-relevant events and monitor them.

```python
import logging

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO)

@app.route('/api/resource/<int:resource_id>', methods=['GET'])
def get_resource(resource_id):
    logging.info(f"Resource {resource_id} accessed by user {current_user.id}")
    resource = get_resource_by_id(resource_id)
    if resource.owner_id != current_user.id:
        logging.warning(f"Unauthorized access attempt by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403
    return jsonify(resource.to_dict())
```

---

#### **11. Protect Sensitive Data**  
**Why**: Prevent leaks of sensitive information during transit or storage.

- [ ] Encrypt sensitive data at rest and in transit (e.g., TLS, encryption libraries).
- [ ] Use environment variables for secrets and keys.

---

#### **12. Secure CORS Configurations**  
**Why**: Prevent unauthorized domains from accessing your API.

- [ ] Restrict allowed origins, methods, and headers.

```python
# Flask-CORS example
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://trusted-origin.com"}})
```

---

### API Security Checklist V1.1
---

#### **Broken Object-Level Authorization**

- [ ] Ensure every API endpoint verifies object ownership before providing access.
- [ ] Validate permissions for each resource request.

#### **Broken User Authentication**

- [ ] Implement secure authentication mechanisms like OAuth2 or JWT.
- [ ] Enforce strong password policies and multi-factor authentication.
- [ ] Monitor login attempts and lock accounts after multiple failures.

#### **Excessive Data Exposure**

- [ ] Restrict API responses to include only necessary fields.
- [ ] Avoid exposing sensitive information such as passwords, tokens, or internal system details.

#### **Lack of Resources & Rate Limiting**

- [ ] Apply rate limits per user or IP address to prevent abuse.
- [ ] Use throttling to mitigate DDoS attacks and brute-force attempts.

#### **Broken Function-Level Authorization**

- [ ] Enforce role-based access control (RBAC) for sensitive functions.
- [ ] Validate user roles and permissions on every request.
- [ ] Avoid exposing admin-only endpoints to unauthorized users.

#### **Mass Assignment**

- [ ] Define and enforce allow-lists for updatable fields in API requests.
- [ ] Block attempts to update restricted or sensitive fields through APIs.

#### **Security Misconfiguration**

- [ ] Disable debug mode and directory indexing on servers.
- [ ] Enforce HTTPS and configure HSTS headers.
- [ ] Regularly review and harden server and framework settings.

#### **Injection**

- [ ] Validate and sanitize all inputs to prevent SQL, NoSQL, and command injections.
- [ ] Use parameterized queries or prepared statements for database interactions.
- [ ] Avoid concatenating inputs directly into queries or commands.

#### **Improper Asset Management**

- [ ] Maintain an updated inventory of APIs, endpoints, and dependencies.
- [ ] Regularly test and review third-party integrations for vulnerabilities.
- [ ] Remove or secure deprecated APIs.

#### **Insufficient Logging & Monitoring**

- [ ] Log all critical actions such as login attempts, failed requests, and data modifications.
- [ ] Monitor logs for unusual activity or patterns.
- [ ] Set up alerts for high-risk events like unauthorized access attempts or spikes in requests.