import psycopg2
import config

class ScannerExecution:

    exec_id = None

    def __init__(self):
        self.exec_id = None
        self.table = "colcert_scanner.scann_exec"
        print("ScannerExecution initialized")

    def _get_connection(self):
        return psycopg2.connect(
            host=config.POSTGRES_HOST,
            database=config.POSTGRES_DB,
            user=config.POSTGRES_USER,
            password=config.POSTGRES_PASSWORD,
            port=config.POSTGRES_PORT
        )

    def create_exec(self, domain: str) -> int:
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO {} (domain, status, report_url)
                        VALUES (%s, %s, %s)
                        RETURNING id
                    """.format(self.table), (domain, "processing", None))

                    exec_id = cursor.fetchone()[0]
                    conn.commit()

                    print(f"🚀 Nueva ejecución iniciada (ID={exec_id}, domain={domain})")
                    self.exec_id = exec_id

                    return exec_id

        except Exception as e:
            print(f"❌ Error creando scann_exec: {e}")
            return -1
        
    
    def mark_done(self, s3_url: str) -> bool:
        try:
            if not self.exec_id:
                raise ValueError("exec_id no está definido")

            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE {}
                        SET status = %s,
                            updated_at = CURRENT_TIMESTAMP,
                            report_url = %s
                        WHERE id = %s
                    """.format(self.table), ("done", s3_url, self.exec_id))

                    conn.commit()

            print(f"✅ Ejecución completada (ID={self.exec_id})")
            return True

        except Exception as e:
            print(f"❌ Error actualizando a done (ID={self.exec_id}): {e}")
            return False
        
    def get_last_execs(self, limit: int = 10):
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, domain, status, report_url, created_at, updated_at
                        FROM {}
                        ORDER BY created_at DESC
                        LIMIT %s
                    """.format(self.table), (limit,))

                    rows = cursor.fetchall()

                    columns = [desc[0] for desc in cursor.description]
                    results = [
                        dict(zip(columns, row))
                        for row in rows
                    ]

                    return results
        except Exception as e:
            print(f"❌ Error obteniendo últimas ejecuciones: {e}")
            return []
        
    def get_exec(self, id: int):
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, domain, status, report_url, created_at, updated_at
                        FROM {}
                        WHERE id = %s
                    """.format(self.table), (id,))

                    row = cursor.fetchone()
                    columns = [desc[0] for desc in cursor.description]
                    result = dict(zip(columns, row)) if row else None
                    return result
        except Exception as e:
            print(f"❌ Error obteniendo ejecución ID={id}: {e}")
            return None