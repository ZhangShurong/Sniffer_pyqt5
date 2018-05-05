#include <qqmlsortfilterproxymodel.h>
#include <sorter.h>
#include <filter.h>

#include <QtQml/QQmlExtensionPlugin>
#include <QtQml/qqml.h>

using namespace qqsfpm;

class QExampleQmlPlugin : public QQmlExtensionPlugin {
        Q_OBJECT
        Q_PLUGIN_METADATA(IID QQmlExtensionInterface_iid)

public:
        void registerTypes(const char *uri) {
                Q_ASSERT(uri == QLatin1String("QQSFPM"));

                qmlRegisterType<QQmlSortFilterProxyModel>(uri, 0, 2, "SortFilterProxyModel");

                qmlRegisterUncreatableType<Sorter>(uri, 0, 2, "Sorter", "Sorter is an abstract class");
                qmlRegisterType<RoleSorter>(uri, 0, 2, "RoleSorter");
                qmlRegisterType<ExpressionSorter>(uri, 0, 2, "ExpressionSorter");

                qmlRegisterUncreatableType<Filter>(uri, 0, 2, "Filter", "Filter is an abstract class");
                qmlRegisterType<ValueFilter>(uri, 0, 2, "ValueFilter");
                qmlRegisterType<IndexFilter>(uri, 0, 2, "IndexFilter");
                qmlRegisterType<RegExpFilter>(uri, 0, 2, "RegExpFilter");
                qmlRegisterType<RangeFilter>(uri, 0, 2, "RangeFilter");
                qmlRegisterType<ExpressionFilter>(uri, 0, 2, "ExpressionFilter");
                qmlRegisterType<AnyOfFilter>(uri, 0, 2, "AnyOf");
                qmlRegisterType<AllOfFilter>(uri, 0, 2, "AllOf");
        }
};

#include "plugin.moc"