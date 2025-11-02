from app import app, db, User, Admin, Flag

def seed_database():
    """
    Clears and seeds the database with all
    challenge flags and the admin user.
    """
    
    with app.app_context():
        

        print("Cleaning old challenge data...")
        db.session.query(Admin).delete()
        db.session.query(Flag).delete()

        print("Creating Admin user...")
        admin_user = Admin(
            username='admin',
            password='super_secret_password_123'
        )
        db.session.add(admin_user)

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
            flag_value='flag{N0sy_N3ighb0ur}', 
            points=200
        )
        misconfig_flag = Flag(
            challenge_name='Robots.txt Recon',
            flag_value='flag{r0b0ts_c4nt_k33p_s3cr3ts}',
            points=50
        )
        upload_flag = Flag(
            challenge_name='Insecure File Upload',
            flag_value='flag{f1le_upl0ad_pwned}',
            points=250
        )
        cmd_flag = Flag(
            challenge_name='OS Command Injection',
            flag_value='flag{sh3ll_c0mm4nd3r}',
            points=300
        )

        db.session.add_all([xss_flag, sqli_flag, idor_flag,misconfig_flag,upload_flag,cmd_flag])
        
        try:
            db.session.commit()
            print("\nDatabase seeding complete!")
        except Exception as e:
            db.session.rollback()
            print(f"\nError seeding database: {e}")

if __name__ == '__main__':
    seed_database()