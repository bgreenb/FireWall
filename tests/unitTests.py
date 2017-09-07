import unittest
import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
import ipruleTest
import readRules

class isInGroup(unittest.TestCase):

   testRulesFile = "testRules.txt"
   testGroupDataFile = "UnitGroups.conf"

   def setUp(self):
      self.rules = readRules.setUp(self.testRulesFile)
      self.groupData = ipruleTest.GroupData(self.testGroupDataFile)
      self.compare = ipruleTest.Comparison(self.rules,self.groupData)

   # Basic Test to check that two IPv4 addresses are from their respective groups
   def testIP1(self):
      self.assertEqual(self.compare.groupMatch("10.6.1.2","10.1.1.20","TestGroup1","TestGroup3"),True)

   # Another basic test to make sure a flow does not get added when the ip address do not match 
   # the groups they are supposed to be in
   def testIP2(self):
      self.assertEqual(self.compare.groupMatch("10.6.1.2","10.1.1.20","TestGroup1","TestGroup4"),False)

   # Test if two given ip addresses belong to the same group that uses a regex pattern to match
   def testIP3(self):
      self.assertEqual(self.compare.groupMatch("192.134.1.204","192.137.1.104","TestGroup5","TestGroup5"),True)
   
   # An address with 135 as its second octet should be rejected by the regex pattern   
   def testIP4(self):
      self.assertEqual(self.compare.groupMatch("192.134.1.204","192.135.1.104","TestGroup5","TestGroup5"),False)
   
   # Test if the source IP is apart of a regex in the source group and part of a subnet in the destination group
   def testSub1(self):
      self.assertEqual(self.compare.groupMatch("192.134.1.204","10.6.1.58","TestGroup5","TestGroup2"),True)
   
   # This should reject as the source IP does not match the regex in its regex.
   def testSub2(self):
      self.assertEqual(self.compare.groupMatch("192.135.1.130","10.6.1.20","TestGroup5","TestGroup2"),False)

   # Test that when both IPs are from subnets of their groups, that it matches. 
   def testSub3(self):
      self.assertEqual(self.compare.groupMatch("192.168.1.24","10.6.1.42","TestGroup1","TestGroup2"),True)

if __name__ == '__main__':
    unittest.main()
     
