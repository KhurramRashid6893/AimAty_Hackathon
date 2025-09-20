Bharat Votes - Next Generation Voting System
Bharat Votes is a comprehensive, Flask-based web application designed to modernize the electoral process through technology. It features voter registration with face capture, secure face verification at polling booths, a real-time ballot machine, and detailed dashboards for administrators and booth officers. The system also includes a complete workflow for candidate nomination and approval by the Election Commission of India (ECI).

Core Features
•	Multilingual Interface: Supports multiple Indian languages including English, Hindi, Marathi, Gujarati, Tamil, Telugu, and Urdu.
•	Voter Registration: A secure signup form for voters to register with their Aadhaar, Voter ID, and a face image for biometric verification.
•	Face Scan Verification: A booth-level face scanning interface to verify a voter's identity against their registered photo before activating the ballot.
•	Real-time Ballot Machine: A digital ballot interface that allows verified voters to cast their vote for registered candidates.
•	Admin & Booth Dashboards: Powerful dashboards for administrators to monitor live election activity and for booth officers to manage manual overrides and view booth-specific data.
•	Candidate Nomination Portal: A complete workflow for candidates to sign up, log in, and submit their nomination forms with required documents.
•	ECI Approval Dashboard: A dedicated portal for the Election Commission of India (ECI) to review, approve, or reject candidate nominations.
________________________________________
File Structure & Descriptions
Here is a breakdown of all the files in the repository and their purpose.

Main Application Files (.py)
•	app.py: The main entry point for the Flask application. It initializes the app, connects to the database, and registers the application's routes.
•	routes.py: The core of the backend logic. It defines all the URL routes for the application, such as /login, /signup, /api/face_scan, etc., and contains the functions that handle user requests and interact with the database.
•	models.py: Defines the database structure using SQLAlchemy. It contains the schema for all tables, including Voter, Candidate, Vote, Admin, BoothOfficer, Nomination, and more.
•	config.py: Contains the configuration settings for the Flask application, including the secret key, database location (election_nominations.db), and the folder for file uploads.
•	utils.py: A utility module that contains helper functions for handling face recognition. This includes functions to save uploaded images, encode faces into a biometric format, and compare two faces to see if they match.
•	reset_db.py and seed_db.py: These are database management scripts. reset_db.py completely wipes and recreates the database tables. seed_db.py populates the database with initial data, such as a default admin, booth officer, and a list of candidates.

Frontend Templates (templates/*.html)
These files define the structure of the web pages that users interact with.
•	index.html & index2.html: The main landing pages for the website, providing an overview of the system and links to different sections.
•	signup.html & login.html: The forms for new voters to register and for all user types (voter, admin, booth officer) to log in.
•	voter_face_scan.html: The user interface for the face verification process at the polling booth. It includes the live camera feed and status updates.
•	admin_dashboard.html & booth_dashboard.html: The dashboard interfaces for administrators and booth officers, showing live data, activity feeds, and management tools.
•	ballot_machine.html & receipt.html: The interfaces for the digital voting machine and the receipt printer, respectively.
•	candidates.html, candidate_login.html, candidate_signup.html, candidate_dashboard.html: A complete set of pages for candidates to submit their nomination, log in, and view the status of their application.
•	eci_login.html & eci_dashboard.html: The secure portal for the Election Commission of India to manage and review candidate nominations.
•	base.html: A base template that other pages extend. It contains the common header and footer, ensuring a consistent look and feel across the site.

Static Assets (static/)
This folder contains all the static files that are served to the user's browser.
•	static/css/layout.css: The main stylesheet that defines the branding, colors, and overall design of the website.
•	static/js/translations.js: A JavaScript file containing all the text translations for the multilingual interface. This allows the site to switch between languages dynamically.
•	static/uploads/: This is the designated folder where all user-uploaded images (voter faces, candidate documents) are stored.
