Java OpenID = JOID

This library lets you create OpenID providers as well as relying parties. Both
OpenID 1.1 and 2.0 is covered. 

See more at <http://code.google.com/p/joid/>

To build:
  $ ant build

For javadocs API docs:
  $ ant api

For unit tests:
  $ ant tests

  NOTE: To run the tests, you need to have a 'joid_test' database. 

  $ mysqladmin -uroot -p<password> create joid_test
  $ mysql -uroot -p<password> -Djoid_test < ./stores/hibernate/src/create.sql


See src/examples for example usage.

See LICENSE.txt for licensing agreement.


