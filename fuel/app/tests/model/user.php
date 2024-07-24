<?php
/**
 * @group App
 * @group Model
 * @group User
 * @group Materia
 */

use \Materia\Widget_Installer;

class Test_Model_User extends \Basetest
{

	public function test_find_by_name_search_doesnt_find_super_users()
	{
		// su should't be found
		$su = $this->make_random_super_user();
		$x = Model_User::find_by_name_search($su->email);
		self::assertEmpty($x);

		// add a student with the same name, should only find the one student
		$this->make_random_student();
		$x = Model_User::find_by_name_search('drop');
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertNotEquals($su->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_students_by_email()
	{
		$user = $this->make_random_student();

		$x = Model_User::find_by_name_search($user->email);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_students_by_first_name()
	{
		$user = $this->make_random_student();

		$x = Model_User::find_by_name_search($user->first);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_students_by_last_name()
	{
		$user = $this->make_random_student();

		$x = Model_User::find_by_name_search($user->last);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_students_by_username()
	{
		$user = $this->make_random_student();

		$x = Model_User::find_by_name_search($user->username);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_students()
	{
		$user = $this->make_random_student();

		$x = Model_User::find_by_name_search($user->email);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_authors()
	{
		$user = $this->make_random_author();
		$x = Model_User::find_by_name_search($user->email);
		self::assertCount(1, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertEquals($user->id, $x[0]->id);
	}

	public function test_find_by_name_search_finds_multiple_matches()
	{
		$user1 = $this->make_random_author();
		$user2 = $this->make_random_student();

		$x = Model_User::find_by_name_search('drop');
		self::assertCount(2, $x);
		self::assertInstanceOf('Model_User', $x[0]);
		self::assertInstanceOf('Model_User', $x[1]);

		$ids = [$x[0]->id, $x[1]->id];

		self::assertContainsEquals($user1->id, $ids);
		self::assertContainsEquals($user2->id, $ids);
	}

}
