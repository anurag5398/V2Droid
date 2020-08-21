from django.db import models

class Project(models.Model):
    md5 = models.TextField(db_column='MD5', primary_key=True)  # Field name made lowercase.
    app_name = models.TextField(blank=True, null=True)
    date = models.TextField(blank=True, null=True)
    time = models.TextField(blank=True, null=True)
    manifest_json = models.TextField(db_column='Manifest_json', blank=True, null=True)  # Field name made lowercase.
    permission_json = models.TextField(db_column='Permission_json', blank=True, null=True)  # Field name made lowercase.
    sha1 = models.TextField(db_column='SHA1', blank=True, null=True)  # Field name made lowercase.
    sha256 = models.TextField(db_column='SHA256', blank=True, null=True)  # Field name made lowercase.
    size = models.TextField(blank=True, null=True)
    package_name = models.TextField(blank=True, null=True)
    main_activity = models.TextField(blank=True, null=True)
    target_sdk = models.TextField(blank=True, null=True)
    max_sdk = models.TextField(blank=True, null=True)
    min_sdk = models.TextField(blank=True, null=True)
    androvername = models.TextField(blank=True, null=True)
    androver = models.TextField(blank=True, null=True)
    cnt_act = models.TextField(blank=True, null=True)
    cnt_pro = models.TextField(blank=True, null=True)
    cnt_ser = models.TextField(blank=True, null=True)
    cnt_bro = models.TextField(blank=True, null=True)
    e_act = models.TextField(blank=True, null=True)
    e_cnt = models.TextField(blank=True, null=True)
    e_ser = models.TextField(blank=True, null=True)
    e_bro = models.TextField(blank=True, null=True)
    cert_info = models.TextField(blank=True, null=True)
    bin_anal_json = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'project'
    def __str__(self):
        return self.app_name

class Jirasession(models.Model):
    username = models.TextField(blank=True, null=True)
    session = models.TextField(primary_key=True, blank=True)
    time = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'jirasession'
    def __str__(self):
        return self.app_name
