import boto3
from pathlib import Path
import config

class UploadReport:

    def __init__(self):
        self.s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            endpoint_url=config.S3_HOST,
            aws_access_key_id=config.S3_ACCESS_KEY,
            aws_secret_access_key=config.S3_SECRET_KEY,
        )
        self.bucket = config.S3_BUCKET

    def upload_report(self, filepath: str) -> str:
        try:
            path = Path(filepath)

            if not path.exists():
                raise FileNotFoundError(f"Archivo no existe: {filepath}")

            report_name = path.name
            s3_key = f"reports/{report_name}"

            with open(path, "rb") as f:
                self.s3.upload_fileobj(
                    f,
                    self.bucket,
                    s3_key,
                    ExtraArgs={
                        "ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    }
                )

            url = f"{config.S3_HOST}/{self.bucket}/{s3_key}"

            print(f"✅ Report {report_name} subido correctamente")
            return url

        except Exception as e:
            print(f"❌ Error subiendo reporte: {e}")
            return ""