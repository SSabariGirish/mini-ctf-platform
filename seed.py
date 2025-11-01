from app import app, db, User, Admin, Flag

def seed_database():
    """
    Clears and seeds the database with all
    challenge flags and the admin user.
    """
    
    with app.app_context():
        
        # --- 1. CLEAN UP OLD DATA ---
        print("Cleaning old challenge data...")
        db.session.query(Admin).delete()
        db.session.query(Flag).delete()
        
        # --- 2. ADD ADMIN USER (for SQLi Challenge) ---
        print("Creating Admin user...")
        admin_user = Admin(
            username='admin',
            password='super_secret_password_123'
        )
        db.session.add(admin_user)

        # --- 3. ADD ALL FLAGS ---
        print("Adding flags to database...")
        xss_flag = Flag(
            challenge_name='Search Page XSS', 
            flag_value='flag{R3fl3ct3d_XSS_is_Fast}', 
            points=100
        )
        sqli_flag = Flag(
            challenge_name='Admin Login SQLi',
            flag_value='flag{SQLi_L0gin_Byp@ss}',
            points=150
        )
        idor_flag = Flag(
            challenge_name='IDOR Profile Page',
            flag_value='flag{N0sy_N3ighb0ur}', # This is the flag they'll find
            points=200
        )
        db.session.add_all([xss_flag, sqli_flag, idor_flag])
        
        # --- 4. COMMIT ALL CHANGES ---
        try:
            db.session.commit()
            print("\n✅ Database seeding complete!")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error seeding database: {e}")

if __name__ == '__main__':
    seed_database()