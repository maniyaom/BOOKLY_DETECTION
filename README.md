# Web Security Enhancement Tool

## Description

This project is designed to enhance the security of web applications by integrating a machine learning model for detecting common web vulnerabilities such as Cross-Site Scripting (XSS) and SQL Injection. The system is built using PHP, MySQL, HTML, CSS, and JavaScript, with a Flask API for model integration and deployment.

## Features

- **Web Application**: Developed using PHP, MySQL, HTML, CSS, and JavaScript.
- **Machine Learning Model**: Utilizes a Random Forest algorithm to detect XSS and SQL Injection attacks with an accuracy of 98%.
- **Flask API Integration**: The ML model is integrated into the web application through a Flask API.
- **DDoS Attack Tool**: Implements a DDoS attack tool using Python libraries for testing purposes.
- **Database Hosting**: MySQL database hosted on Aiven for dynamic data handling.
- **Domain Configuration**: The website is connected to the domain linef.us.

## Technologies Used

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: PHP
- **Database**: MySQL
- **Machine Learning**: Python (scikit-learn)
- **API Framework**: Flask
- **Deployment**: Render.com for Flask API; InfinityFree.com for PHP website hosting

## Installation

### Prerequisites

- Python 3.x
- PHP 7.x or higher
- MySQL Server
- Flask
- Required Python libraries listed in `requirements.txt`

### Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/reponame.git
   cd reponame
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up your MySQL database using Aiven and configure your connection settings in `app.py`.

4. Deploy the PHP website on InfinityFree.com and connect it to your domain linef.us.

5. For the Flask API:
   - Deploy it on Render.com following their deployment instructions.

6. Run the Flask application:
   ```bash
   python app.py
   ```

## Usage

Once everything is set up:

1. Access your PHP website through your domain (linef.us).
2. The integrated ML model will monitor incoming requests and detect potential XSS and SQL Injection attacks.
3. Use the DDoS attack tool responsibly for testing purposes only.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors and libraries that made this project possible.
  
Feel free to contribute by opening issues or submitting pull requests!
