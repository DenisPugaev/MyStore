angular.module('my-market').controller('storeController', function ($scope, $http, $location, $localStorage) {
    const contextPath = 'http://localhost:8080/app/';

    $scope.loadProducts = function (pageIndex = 1) {
        $http({
            url: contextPath + 'api/v1/products',
            method: 'GET',
            params: {
                page: pageIndex,
                min_price: $scope.filter ? $scope.filter.min_price : null,
                max_price: $scope.filter ? $scope.filter.max_price : null,
                title_part: $scope.filter ? $scope.filter.title_part : null
            }
        }).then(function (response) {
            $scope.ProductList = response.data.content;
        });
    };

    $scope.resetForm = function() {
        $scope.filter.min_price = null;
        $scope.filter.max_price = null;
        $scope.filter.title_part = null;
        $scope.loadProducts();
    };

    $scope.deleteProduct = function (productId) {
        console.log('Click deleteProduct', productId);
        $http.delete(contextPath + 'admin/product/' + productId)
            .then(function successCallback(response) {
                alert('Продукт удален ID: ' + productId);
                $scope.loadProducts();
            }, function errorCallback(response) {
                alert('Нет прав на удаление товара!');
            });

    }





    $scope.addToCart = function (productId) {
        $http.get(contextPath+'api/v1/cart/add/' + productId)
            .then(function (response) {
            });
    }

    $scope.loadOrders = function () {
        $http.get(contextPath + 'api/v1/orders')
            .then(function (response) {
                $scope.MyOrders = response.data;
            });
    }

    $scope.loadProducts();
    $scope.loadOrders();
});