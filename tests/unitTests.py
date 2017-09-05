import unittest
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

   # Test if two given ip addresses belong to the same group that uses a regex pattern to match
   def testIP2(self):
      self.assertEqual(self.compare.groupMatch("192.134.1.204","192.137.1.104","TestGroup5","TestGroup5"),True)
   
   # An address with 135 as its second octet should be rejected by the regex pattern   
   def testIP3(self):
      self.assertEqual(self.compare.groupMatch("192.134.1.204","192.135.1.104","TestGroup5","TestGroup5"),False)

if __name__ == '__main__':
    unittest.main()
     
