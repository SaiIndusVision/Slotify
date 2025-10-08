from django.contrib import admin
from .models import Slot, Category, Booking
# Register your models here.
admin.site.register(Slot)
admin.site.register(Category)
admin.site.register(Booking)