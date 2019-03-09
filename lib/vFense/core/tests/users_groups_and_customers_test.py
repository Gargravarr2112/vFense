import unittest

from vFense.core._constants import *
from vFense.core.user._constants import *
from vFense.core.user.users import *
from vFense.core.group.groups import *
from vFense.core.group._constants import *
from vFense.core.customer.customers import *
from vFense.core.customer._constants import *
from vFense.core.permissions._constants import *
from vFense.errorz._constants import *

class UsersGroupsAndCustomersTests(unittest.TestCase):

    def test_a_create_customer(self):
        results = (
            create_customer(
                'test',
                http_application_url_location='https://10.0.0.1/packages',
                init=True
            )
        )
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_b_edit_customer(self):
        props = {
            CustomerKeys.OperationTtl: 20
        }
        results = edit_customer('test', **props)
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_c_create_group1(self):
        results = (
            create_group(
                'Tester 4 life Part 1', 'test', [Permissions.ADMINISTRATOR]
            )
        )
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_d_create_group2(self):
        results = (
            create_group(
                'Tester 4 life Part 2', 'test',
                [Permissions.INSTALL, Permissions.UNINSTALL]
            )
        )
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)


    def test_e_create_user1(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 1', 'test').get(GroupKeys.GroupId)
        )
        results = create_user(
            'test1', 'Unit Test 1', 'T35t#123',
            [group_test_id], 'test', 'test@test.org', 'yes',
            'tester', '/test', 'TEST'
        ) 
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_f_create_user2(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 1', 'test').get(GroupKeys.GroupId)
        )
        results = create_user(
            'test2', 'Unit Test 2', 'T35t#123',
            [group_test_id], 'test', 'test@test.org', 'yes',
            'tester', '/test', 'TEST'
        ) 
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_g_create_user3(self):
        group_test_id_1 = (
            get_group_by_name('Tester 4 life Part 1', 'test').get(GroupKeys.GroupId)
        )
        group_test_id_2 = (
            get_group_by_name('Tester 4 life Part 2', 'test').get(GroupKeys.GroupId)
        )
        results = create_user(
            'test3', 'Unit Test 3', 'T35t#123',
            [group_test_id_1, group_test_id_2],
            'test', 'test@test.org', 'yes',
            'tester', '/test', 'TEST'
        ) 
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_h_edit_user(self):
        props = {
            UserKeys.FullName: 'Ninja Unit Tester 1'
        }
        results = edit_user_properties('test1', **props)
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_i_edit_password(self):
        results = change_password('test1', 'T35t#123', 'T35t#1234')
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_j_add_user_to_group(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 2', 'test').get(GroupKeys.GroupId)
        )
        results = add_user_to_groups('test2', 'test', [group_test_id])
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)
    def test_k_remove_groups_from_user(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 1', 'test').get(GroupKeys.GroupId)
        )
        results = remove_groups_from_user('test3', [group_test_id])
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)
#"""

    def test_l_remove_customers_from_user(self):
        results = remove_customers_from_user('test3', ['test'])
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)


    def test_m_remove_user(self):
        results = remove_user('test3')
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_n_remove_users(self):
        results = remove_users(['test1', 'test2'])
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_o_remove_groups1(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 1', 'test').get(GroupKeys.GroupId)
        )
        results = remove_group(group_test_id)
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_p_remove_groups2(self):
        group_test_id = (
            get_group_by_name('Tester 4 life Part 2', 'test').get(GroupKeys.GroupId)
        )
        results = remove_group(group_test_id)
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)

    def test_q_remove_customer1(self):
        results = remove_customer('test')
        http_status_code = results.get(ApiResultKeys.HTTP_STATUS_CODE)
        self.assertTrue(http_status_code == 200)


#"""
    #def testTwo(self):
    #    self.failIf(IsOdd(2))

def main():
    unittest.main()

if __name__ == '__main__':
    main()
