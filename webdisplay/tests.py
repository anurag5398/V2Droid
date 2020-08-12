from django.test import TestCase

# Create your tests here.
from django.core.files.uploadedfile import SimpleUploadedFile

def test_upload_video(self):
    video = SimpleUploadedFile("file.mp4", "file_content", content_type="video/mp4")
    self.client.post(reverse('app:some_view'), {'video': video})