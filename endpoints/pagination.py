from rest_framework import pagination


class pagination_rest(pagination.PageNumberPagination):
    page_size = 2
    page_query_description = 'page'
