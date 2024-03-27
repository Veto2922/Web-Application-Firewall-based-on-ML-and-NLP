**Web Application Firewall (WAF) Project**

---

**Introduction:**

The Web Application Firewall (WAF) project is aimed at developing a robust and comprehensive solution to safeguard web applications against a wide range of security threats. The project incorporates machine learning techniques for threat detection, real-time monitoring, and response mechanisms to protect web applications from common attacks such as Cross-Site Scripting (XSS), SQL Injection (SQLI), Command Injection (CMDI), and Path Traversal (PATHT).

![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/37280381-c058-48cc-bb13-1836002c1ee8)

---

**Project Paper:** [Project Paper Link](https://drive.google.com/file/d/1xhJiBsxgZ-nALevpSkK9f_Lcj4FGQE2c/view)

**Project Video:** [Project Video Link](https://drive.google.com/file/d/1-UlhEx3tYo8vXR7kRDoakTFnEed10TML/view)

**Project Website:** [Project Website Link](https://waf-app.onrender.com/login?next=%2F)

---

**Project Overview:**

The WAF project consists of two main stages:

1. **First Stage:**
   - In the initial stage, the project focuses on sniffing HTTP traffic on the public internet and analyzing HTTP headers along with other relevant information.
   - The HTTP requests are then processed by a machine learning-based classifier to determine whether they are valid or malicious.
   - Valid requests are forwarded to the server, while malicious requests are dropped, and alerts are sent via WhatsApp.
   - The geolocation of the IP addresses associated with the malicious requests is determined and sent to a dashboard for monitoring purposes.
     ![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/735116f1-6b71-40fa-8dbd-e3ec9644ade1)


2. **Second Stage:**
   - The second stage involves integrating the WAF functionality into a web application.
   - Requests originating from the web application are intercepted by the WAF before reaching the server.
   - The WAF analyzes the requests using the same classifier from the first stage and takes appropriate action based on the classification results.
   - Valid requests are forwarded to the server, while malicious requests are dropped, and alerts are sent via WhatsApp.
   - Geolocation information is also collected and sent to the monitoring dashboard.
     ![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/601dd976-97ec-46b2-b012-a1a9b4d3a2ee)


---

**Project Components:**

1. **Classifier:**
   - The classifier module is responsible for processing HTTP requests and determining whether they are valid or malicious.
   - It utilizes machine learning algorithms trained on labeled datasets to classify incoming requests.
     ![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/229a56bc-498a-4ad3-a598-dc362a2be46d)


2. **Web Application Firewall (WAF) Code:**
   - The WAF code intercepts incoming HTTP requests and passes them to the classifier for analysis.
   - Based on the classification results, it either forwards the requests to the server or drops them and triggers alerts.
     
   ![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/f41c9147-b58e-4a96-8129-781498b6125f)

3. **Request Handler:**
   - The request handler module manages the processing of requests and responses between the WAF, classifier, server, and database.
   - It formats the request data, calculates statistics, and stores the information in a MongoDB database.
     ![image](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/22ea3d1e-2d50-442b-b78f-e0b3f5c02c28)


4. **Dashboard:**
   - The dashboard provides real-time monitoring and visualization of incoming requests, classifications, and geolocation data.
   - It helps administrators to track and analyze potential security threats.
     ![Screenshot 2023-12-24 003841](https://github.com/Veto2922/Web-Application-Firewall-based-on-ML-and-NLP/assets/114834171/31bacebc-2d26-4bad-87ba-6ffc3fccca9f)

5. **Web Application:**
   - The web application serves as a testbed for integrating the WAF functionality.
   - It includes login, signup, and home pages, allowing users to interact with the application and generate HTTP requests.

6. **Web Server:**
   - Radner web server is used to deploy the web application and host the WAF functionality.
   - Render.com is utilized as the hosting platform, providing automated scaling, SSL certificates, and serverless functions.


---



