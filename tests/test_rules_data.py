import unittest

from helpers import scan_files


def run(code, path="src/main/java/Repo.java"):
    return [f for f in scan_files({path: code}) if f["id"] == "SEC022"]


def wrap(body):
    return "class Repo { void f() { " + body + " } }"


class Sec022(unittest.TestCase):
    def test_concatenated_sql_is_reported(self):
        for body in ['em.createNativeQuery("select * from u where n = \'" + name + "\'");',
                     'em.createQuery("from User where name = " + n);',
                     'jdbc.query("select * from t where id = " + id, mapper);',
                     'jdbc.update("delete from t where id = " + id);',
                     'stmt.executeQuery("select * from t where x = " + x);',
                     'jdbc.queryForList(String.format("select * from t where id = %s", id));']:
            found = run(wrap(body))
            self.assertEqual(len(found), 1, body)
            self.assertEqual((found[0]["severity"], found[0]["confidence"], found[0]["category"]),
                             ("high", "medium", "data_logging"))

    def test_parameterized_and_constant_sql_is_fine(self):
        for body in ['jdbc.query("select * from t where id = ?", mapper, id);',
                     'em.createQuery("from User where name = :n").setParameter("n", n);',
                     'jdbc.update("update t set a = 1 " + "where id = 2");',
                     'service.update(first + second);',
                     'jdbc.execute("select 1");']:
            self.assertEqual(run(wrap(body)), [], body)

    def test_comment_and_test_sources_are_ignored(self):
        self.assertEqual(run(wrap('// jdbc.update("delete from t where id = " + id);')), [])
        self.assertEqual(run(wrap('jdbc.update("delete from t where id = " + id);'), "src/test/java/RepoTest.java"), [])


if __name__ == "__main__":
    unittest.main()
