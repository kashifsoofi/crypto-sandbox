# How to run tests
Download [gson-2.8.6](https://search.maven.org/remotecontent?filepath=com/google/code/gson/gson/2.8.6/gson-2.8.6.jar), [junit-4.12](https://github.com/junit-team/junit4/releases/download/r4.12/junit-4.12.jar) and [hamcrest-core-1.3](http://search.maven.org/remotecontent?filepath=org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar)  
1. Compile class  
`javac -cp .:gson-2.8.6.jar RsaCrypto.java`  
2. Compile test class. On Linux or MacOS  
`javac -cp .:junit-4.12.jar:hamcrest-core-1.3.jar RsaCryptoTests.java`  
and on Windows  
`javac -cp .;junit-4.12.jar;hamcrest-core-1.3.jar RsaCryptoTests.java`  
3. Run tests. On Linux or MacOS  
`java -cp .:gson-2.8.6.jar:junit-4.12.jar:hamcrest-core-1.3.jar org.junit.runner.JUnitCore RsaCryptoTests`  
and on Windows
`java -cp .;junit-4.12.jar;hamcrest-core-1.3.jar org.junit.runner.JUnitCore RsaCryptoTests`  

If there is an InvalidKeyException Illegal key size exception, have a look at following stackoverflow post https://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size
