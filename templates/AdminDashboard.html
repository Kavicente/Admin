<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/admin.css') }}">
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <script>
        const socket = io('https://alert-858l.onrender.com');
        socket.on('connect', () => {
            console.log('Connected to WebSocket');
        });

        socket.on('new_user', (user) => {
            fetchUsers(); // Refresh tables on new signup
        });


        async function fetchUsers() {
            try {
                const response = await fetch('https://alert-858l.onrender.com/api/get_all_users');
                const users = await response.json();
                updateTables(users);
            } catch (error) {
                console.error('Error fetching users:', error);
            }
        }

        function updateTables(users) {
            const allTable = document.getElementById('all-accounts-table').getElementsByTagName('tbody')[0];
            const residentTable = document.getElementById('resident-accounts-table').getElementsByTagName('tbody')[0];
            const barangayTable = document.getElementById('barangay-accounts-table').getElementsByTagName('tbody')[0];
            const agenciesTable = document.getElementById('agencies-accounts-table').getElementsByTagName('tbody')[0];

            allTable.innerHTML = '';
            residentTable.innerHTML = '';
            barangayTable.innerHTML = '';
            agenciesTable.innerHTML = '';

            users.forEach(user => {
                const row = `
                    <tr>
                        <td>${user.source}</td>
                        <td>${user.role}</td>
                        <td>${user.username || user.contact_no}</td>
                        <td>${user.first_name} ${user.middle_name} ${user.last_name}</td>
                        <td>${user.barangay || ''}</td>
                        <td>${user.municipality || ''}</td>
                        <td>${user.status}</td>
                        <td>
                            ${user.source === 'android' && user.role === 'resident' ? `
                                <button onclick="updateStatus('${user.source}', '${user.username}', 'active')">Activate</button>
                                <button onclick="updateStatus('${user.source}', '${user.username}', 'warning')">Warn</button>
                                <button onclick="updateStatus('${user.source}', '${user.username}', 'suspended')">Suspend</button>
                                <button onclick="deleteUser('${user.source}', '${user.username}')">Delete</button>
                            ` : ''}
                        </td>
                    </tr>
                `;
                allTable.insertAdjacentHTML('beforeend', row);
                if (user.source === 'android' && user.role === 'resident') {
                    residentTable.insertAdjacentHTML('beforeend', row);
                }
                if (user.role === 'barangay') {
                    barangayTable.insertAdjacentHTML('beforeend', row);
                }
                if (user.role in ['cdrrmo', 'pnp', 'bfp']) {
                    agenciesTable.insertAdjacentHTML('beforeend', row);
                }
            });
        }

        async function updateStatus(source, identifier, status) {
            try {
                const response = await fetch(`/admin/update_status/${source}/${identifier}/${status}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                if (response.ok) {
                    alert('Status updated successfully');
                    fetchUsers();
                } else {
                    alert('Failed to update status');
                }
            } catch (error) {
                console.error('Error updating status:', error);
                alert('Error updating status');
            }
        }

        async function deleteUser(source, identifier) {
            if (confirm('Are you sure you want to delete this user?')) {
                try {
                    const response = await fetch(`/admin/delete_user/${source}/${identifier}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    if (response.ok) {
                        alert('User deleted successfully');
                        fetchUsers();
                    } else {
                        alert('Failed to delete user');
                    }
                } catch (error) {
                    console.error('Error deleting user:', error);
                    alert('Error deleting user');
                }
            }
        }

        function showTab(tabId) {
            document.querySelectorAll('.section').forEach(section => {
                section.classList.add('hidden');
            });
            document.getElementById(tabId).classList.remove('hidden');
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.getElementById(`tab-${tabId}`).classList.add('active');
        }

        window.onload = () => {
            fetchUsers();
            showTab('all-accounts');
        };
    </script>
</head>
<body>
    <div class="sidebar">
        
        <nav>
            <ul>
                <li><a href="#" onclick="showTab('all-accounts')" id="tab-all-accounts" class="tab active">All Accounts</a></li>
                <li><a href="#" onclick="showTab('resident-accounts')" id="tab-resident-accounts" class="tab">Resident Accounts</a></li>
                <li><a href="#" onclick="showTab('barangay-accounts')" id="tab-barangay-accounts" class="tab">Barangay Accounts</a></li>
                <li><a href="#" onclick="showTab('agencies-accounts')" id="tab-agencies-accounts" class="tab">Agencies Accounts</a></li>
                <li><a href="{{ url_for('logout') }}"><span>🚪</span> Log Out</a></li>
            </ul>
        </nav>
    </div>
    <div class="main-content">
        <button class="toggle-btn" onclick="document.querySelector('.sidebar').classList.toggle('open'); document.querySelector('.main-content').classList.toggle('shifted');">☰</button>
        <header>
            <h1 class="h1">Admin Dashboard</h1>
        </header>
        <div class="section" id="all-accounts">
            <h2>All Accounts</h2>
            <table id="all-accounts-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Role</th>
                        <th>Identifier</th>
                        <th>Name</th>
                        <th>Barangay</th>
                        <th>Municipality</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="section hidden" id="resident-accounts">
            <h2>Resident Accounts</h2>
            <table id="resident-accounts-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Role</th>
                        <th>Identifier</th>
                        <th>Name</th>
                        <th>Barangay</th>
                        <th>Municipality</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="section hidden" id="barangay-accounts">
            <h2>Barangay Accounts</h2>
            <table id="barangay-accounts-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Role</th>
                        <th>Identifier</th>
                        <th>Name</th>
                        <th>Barangay</th>
                        <th>Municipality</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="section hidden" id="agencies-accounts">
            <h2>Agencies Accounts</h2>
            <table id="agencies-accounts-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Role</th>
                        <th>Identifier</th>
                        <th>Name</th>
                        <th>Barangay</th>
                        <th>Municipality</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
</body>
</html>
