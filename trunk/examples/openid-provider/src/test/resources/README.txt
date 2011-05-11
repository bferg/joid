JOID-OP-RP-TestPlan.jmx is a JMeter test plan.
It is ready to open and run from JMeter after starting openid-provider and relying-party example web applications at localhost port 8180 and 8080 respectively.

http://localhost:8080 -> relying-party app (RP)
http://loalhost:8180 -> openid-provider app (OP)

Test includes 300 threads looping 10 times, each realizing a typical usecase in which an unregistered user (with a randomly generated username) wants to login to RP, RP delegates authentication to OP, then user registers to OP and is redirected to RP after successful login.
    