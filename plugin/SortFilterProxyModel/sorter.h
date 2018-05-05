#ifndef SORTER_H
#define SORTER_H

#include <QObject>
#include <QQmlExpression>
#include "qqmlsortfilterproxymodel.h"

namespace qqsfpm {

class Sorter : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(bool ascendingOrder READ ascendingOrder WRITE setAscendingOrder NOTIFY sortOrderChanged)
    Q_PROPERTY(Qt::SortOrder sortOrder READ sortOrder WRITE setSortOrder NOTIFY sortOrderChanged)
    friend class QQmlSortFilterProxyModel;

public:
    Sorter(QObject* parent = nullptr);
    virtual ~Sorter() = 0;

    bool enabled() const;
    void setEnabled(bool enabled);

    bool ascendingOrder() const;
    void setAscendingOrder(bool ascendingOrder);

    Qt::SortOrder sortOrder() const;
    void setSortOrder(Qt::SortOrder sortOrder);

    int compareRows(const QModelIndex& source_left, const QModelIndex& source_right) const;

Q_SIGNALS:
    void enabledChanged();
    void sortOrderChanged();

    void invalidate();

protected:
    QQmlSortFilterProxyModel* proxyModel() const;

    virtual int compare(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const;
    virtual bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const;
    virtual void proxyModelCompleted();
    void sorterChanged();

private:
    bool m_enabled = true;
    Qt::SortOrder m_sortOrder = Qt::AscendingOrder;
    QQmlSortFilterProxyModel* m_proxyModel = nullptr;
};

class RoleSorter : public Sorter
{
    Q_OBJECT
    Q_PROPERTY(QString roleName READ roleName WRITE setRoleName NOTIFY roleNameChanged)

public:
    using Sorter::Sorter;

    const QString& roleName() const;
    void setRoleName(const QString& roleName);

Q_SIGNALS:
    void roleNameChanged();

protected:
    int compare(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;

private:
    QString m_roleName;
};

class ExpressionSorter : public Sorter
{
    Q_OBJECT
    Q_PROPERTY(QQmlScriptString expression READ expression WRITE setExpression NOTIFY expressionChanged)

public:
    using Sorter::Sorter;

    const QQmlScriptString& expression() const;
    void setExpression(const QQmlScriptString& scriptString);

Q_SIGNALS:
    void expressionChanged();

protected:
    int compare(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;
    void proxyModelCompleted() override;

private:
    void updateContext();
    void updateExpression();

    QQmlScriptString m_scriptString;
    QQmlExpression* m_expression = nullptr;
    QQmlContext* m_context = nullptr;
};

}

#endif // SORTER_H
