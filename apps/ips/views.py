from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from .models import IPAddress


@login_required
def ip_list(request):
    queryset = IPAddress.objects.all()
    query = request.GET.get("q", "").strip()
    if query:
        queryset = queryset.filter(address__icontains=query)

    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "ips/list.html", {"page_obj": page_obj, "query": query})
