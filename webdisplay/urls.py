from django.urls import path
from . import views
from webdisplay import views

urlpatterns = [
    path("", views.upload, name = "upload"),
    path('recentscan/', views.tableoutput,),
    path('scan/', views.upload,),
    path('report/', views.eachoutput,),
    path('documentation/', views.documentation,),
    path('pdfgen/',views.pdfgen),
    #path('logs/',views.logview),
    #path('error/',views.base_error),
    #path('jirasession/',views.jirasession),
    #path('base_delete/',views.base_delete),
    path('dashboard/',views.dashboard),
    path('versioncompare/',views.versioncompare,),
    path('compare/',views.compare_project,),
    path('projects/',views.listprojects,),
    path('recentscan/project/',views.viewapk,),	
    path('logs/',views.logsview,),
	path('report/manifest/',views.manifest,),
	path('report/missing/',views.missingapks,),
	path('report/findmissed/', views.findmissing,),
	path('apk-extractor/',views.apkextractor,),
]