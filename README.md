# DetectAD
DetectedAD is my final android project application that use VirusTotal API in order to scan and figure out whether link is malicious or not.

Application screens:
  1. Register/ login screen
  2. Main screen
  3. URL scan screen 
  4. IOCs Feed screen
  5. New Post Screen


Register/ Login screen:
Communicating with Firebase authentication, the user can register or login to his own account.
![alt text](https://firebasestorage.googleapis.com/v0/b/detectad-3314b.appspot.com/o/1.png?alt=media&token=a2625da8-39d4-4a22-a426-545bea9f9161)

Main screen:
The user can choose whether he want to scan URL indicators or view/ create IOC (indication of compromished) post:

![alt text](https://firebasestorage.googleapis.com/v0/b/detectad-3314b.appspot.com/o/2.png?alt=media&token=b245952b-7cd3-4eb4-8372-3a9ce9fab0c5)

URL scan screen:
The user insert URL into the field in order to figure out whether URL (even full path link) having malicious indicators or not:

![alt text](https://firebasestorage.googleapis.com/v0/b/detectad-3314b.appspot.com/o/3.png?alt=media&token=fa8ee5dd-c931-45d3-b89a-dd7355816f72)

IOCs Feed screen:
Each user can post a feed to share suspicious indicators that he found:

![alt text](https://firebasestorage.googleapis.com/v0/b/detectad-3314b.appspot.com/o/4.png?alt=media&token=d9e192e0-c62f-402f-8ab7-52797ae843b1)

New Post screen: 
Using firebase I storing new data and user android view table in order to show the data that locate on firebase database:

![alt text](https://firebasestorage.googleapis.com/v0/b/detectad-3314b.appspot.com/o/5.png?alt=media&token=8ab844c0-c403-4acc-bde9-77e949e6d0ea)
